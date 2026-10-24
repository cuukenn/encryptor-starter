package io.github.cuukenn.encryptor.reactive.gateway.filter;

import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayContext;
import io.github.cuukenn.encryptor.reactive.gateway.runtime.CryptoExecutor;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.RejectedExecutionException;
import java.util.UUID;

/**
 * 网关响应过滤器：仅对"本次请求成功解密"的流量加密回写（{@code {"jwe":"…"}}）。
 * 链后（组装响应时）判响应 content-type 黑名单；超 max-response-size ⇒ 500 不发明文。
 *
 * @author changgg
 */
public class EncryptorResponseFilter implements GlobalFilter, Ordered {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorResponseFilter.class);
    private static final byte[] JWE_PREFIX = "{\"jwe\":\"".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] JWE_SUFFIX = "\"}".getBytes(StandardCharsets.US_ASCII);

    private final GatewayEncryptorConfig config;
    private final EncryptorConfig reactiveConfig;
    private final DefaultProtocol protocol;
    private final CryptoExecutor crypto;

    public EncryptorResponseFilter(GatewayEncryptorConfig config, EncryptorConfig reactiveConfig,
                                   DefaultProtocol protocol, CryptoExecutor crypto) {
        this.config = config;
        this.reactiveConfig = reactiveConfig;
        this.protocol = protocol;
        this.crypto = crypto;
    }

    @Override
    public int getOrder() {
        return config.getFilterConfig().getEncryptorResFilterOrder();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        GatewayContext ctx = exchange.getAttribute(GatewayConstant.GATEWAY_CONTEXT_ATTR);
        if (ctx == null || !ctx.isEncrypted() || protocol.runtime().bypassResponse()) {
            return chain.filter(exchange);
        }
        ServerHttpResponse response = exchange.getResponse();
        // 在装饰期捕获：响应写出可能晚于上游清理，避免 writeWith 里再读 GatewayContext 时被清空
        JweContext jweContext = ctx.getJweContext();
        // 复制 CEK/enc：客户端断连时 doFinally 会在 event-loop 线程清零原数组，
        // 而加密在 crypto 线程上读它；使用副本避免读到半清零的密钥。
        // 跳过/透传路径可能没有 JweContext（例如只声明 encrypted 的配置态），保持空值走原链路。
        byte[] cek = jweContext == null ? null : jweContext.cek().clone();
        String enc = jweContext == null ? null : jweContext.enc();
        ServerHttpResponseDecorator decorated = new ServerHttpResponseDecorator(response) {
            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                if (isNoBodyResponse()) {
                    return completeEmpty();
                }
                // 与请求侧同口径：media-type 段（剥 ;charset= 等参数）小写归一后匹配
                String resCt = StrKit.mediaType(getHeaders().getContentType() == null
                    ? null : getHeaders().getContentType().toString().toLowerCase(java.util.Locale.ROOT));
                if (resCt == null) {
                    resCt = "";
                }
                if (StrKit.anyMatch(resCt, config.getSkipResContentType())) {
                    return super.writeWith(body);
                }
                // 必须在读取过程中限长：先 join 再判长度时，整个响应已经进了堆
                long maxBytes = reactiveConfig.getMaxResponseSize();
                int joinLimit = maxBytes > 0 ? (int) Math.min(maxBytes, Integer.MAX_VALUE) : -1;
                return DataBufferUtils.join(body, joinLimit)
                    // 空 body 也要补一个空 buffer：3xx 走 completeEmpty（不加密），
                    // 200/201 等则封装成 {"jwe":"<空明文>"}，保证客户端拿到的始终是 JWE 信封。
                    .switchIfEmpty(Mono.defer(() -> Mono.just(getDelegate().bufferFactory().wrap(new byte[0]))))
                    .flatMap(buffer -> {
                        byte[] bytes = new byte[buffer.readableByteCount()];
                        buffer.read(bytes);
                        DataBufferUtils.release(buffer);
                        if (bytes.length == 0 && isRedirect()) {
                            return completeEmpty();
                        }
                        if (maxBytes > 0 && bytes.length > maxBytes) {
                            logger.error("响应体超过 max-response-size: {}, 不发明文, uri: {}",
                                bytes.length, exchange.getRequest().getURI().getPath());
                            java.util.Arrays.fill(bytes, (byte) 0);
                            return fail(HttpStatus.INTERNAL_SERVER_ERROR);
                        }
                        if (cek == null) {
                            java.util.Arrays.fill(bytes, (byte) 0);
                            return fail(HttpStatus.INTERNAL_SERVER_ERROR);
                        }
                        // 响应 AAD 的 uri 与请求侧同口径（canonicalPath 归一）：claim 与请求验证
                        // 用同一个规范化形态，客户端按封包路径验响应才不会分叉
                        String uri = ContextAad.canonicalPath(exchange.getRequest().getURI().getPath(), null);
                        String method = exchange.getRequest().getMethod().name();
                        // 显式带上请求协商出的 enc（C2）：SM4-GCM 的 CEK 是 16B，按长度猜会封成 A128GCM
                        return Mono.fromCallable(() -> protocol.codec().encryptResponse(
                                bytes, cek, enc, uri, method,
                                System.currentTimeMillis(), UUID.randomUUID().toString()))
                            .subscribeOn(crypto.scheduler())
                            .doFinally(signal -> {
                                // 加密终态（成功/失败/取消）立即清零两份"明文等价"副本，不等 GC
                                java.util.Arrays.fill(cek, (byte) 0);
                                java.util.Arrays.fill(bytes, (byte) 0);
                            })
                            .flatMap(jwe -> {
                                byte[] jweBytes = jwe.getBytes(StandardCharsets.US_ASCII);
                                byte[] payload = new byte[JWE_PREFIX.length + jweBytes.length + JWE_SUFFIX.length];
                                System.arraycopy(JWE_PREFIX, 0, payload, 0, JWE_PREFIX.length);
                                System.arraycopy(jweBytes, 0, payload, JWE_PREFIX.length, jweBytes.length);
                                System.arraycopy(JWE_SUFFIX, 0, payload, JWE_PREFIX.length + jweBytes.length,
                                    JWE_SUFFIX.length);
                                getHeaders().setContentType(MediaType.APPLICATION_JSON);
                                // body 已被换成 JWE JSON：下游若声明 Content-Encoding（如 gzip）必须去掉，
                                // 否则客户端按 gzip 解压 JWE JSON 得到乱码
                                getHeaders().remove(HttpHeaders.CONTENT_ENCODING);
                                getHeaders().setContentLength(payload.length);
                                return super.writeWith(Mono.just(getDelegate().bufferFactory().wrap(payload)));
                            })
                            .onErrorResume(RejectedExecutionException.class, e -> {
                                // 与请求侧一致：队列满 = 503（可重试），不是 500
                                logger.warn("响应加密被拒绝（队列满）, uri: {}", uri);
                                return fail(HttpStatus.SERVICE_UNAVAILABLE);
                            })
                            .onErrorResume(Throwable.class, e -> {
                                logger.error("响应加密失败, uri: {}", uri, e);
                                return fail(HttpStatus.INTERNAL_SERVER_ERROR);
                            });
                    })
                    .onErrorResume(DataBufferLimitException.class, e -> {
                        logger.error("响应体超过 max-response-size, 不发明文, uri: {}",
                            exchange.getRequest().getURI().getPath());
                        return fail(HttpStatus.INTERNAL_SERVER_ERROR);
                    });
            }

            @Override
            public Mono<Void> writeAndFlushWith(Publisher<? extends Publisher<? extends DataBuffer>> body) {
                if (isNoBodyResponse()) {
                    return completeEmpty();
                }
                // 与请求侧同口径：media-type 段（剥 ;charset= 等参数）小写归一后匹配
                String resCt = StrKit.mediaType(getHeaders().getContentType() == null
                    ? null : getHeaders().getContentType().toString().toLowerCase(java.util.Locale.ROOT));
                if (resCt == null) {
                    resCt = "";
                }
                if (StrKit.anyMatch(resCt, config.getSkipResContentType())) {
                    return super.writeAndFlushWith(body);
                }
                // 流式响应必须和普通响应走同一条加密路径：先按 max-response-size 有界聚合成一个 JWE；
                // 真正的无限流（SSE）请配置 skip-res-content-type 透传，否则会在上限处失败而不是发明文。
                Flux<DataBuffer> flattened = Flux.from(body)
                    .concatMap(inner -> Flux.from(inner).cast(DataBuffer.class));
                return writeWith(flattened);
            }

            /** HEAD、1xx、204/205/304 按 HTTP 语义不产生 body，不能改成 JWE。 */
            private boolean isNoBodyResponse() {
                HttpStatusCode status = getStatusCode();
                int code = status == null ? HttpStatus.OK.value() : status.value();
                return "HEAD".equalsIgnoreCase(exchange.getRequest().getMethod().name())
                    || (code >= 100 && code < 200) || code == 204 || code == 205 || code == 304;
            }

            /** 3xx 允许带说明性 body；只有空 body 才按无 body 透传。 */
            private boolean isRedirect() {
                HttpStatusCode status = getStatusCode();
                int code = status == null ? HttpStatus.OK.value() : status.value();
                return code >= 300 && code < 400;
            }

            /** 无 body 响应统一出口：保留状态/Location，去掉 Content-Length，不写 body。 */
            private Mono<Void> completeEmpty() {
                getHeaders().remove(HttpHeaders.CONTENT_LENGTH);
                if (getStatusCode() == null) {
                    setStatusCode(HttpStatus.OK);
                }
                return setComplete();
            }

            /** 失败面统一出口：body 清空、去 Content-Encoding、带 trace 头与状态码（不发明文）。 */
            private Mono<Void> fail(HttpStatus status) {
                getHeaders().remove(HttpHeaders.CONTENT_ENCODING);
                getHeaders().set(HttpHeaders.CONTENT_LENGTH, "0");
                getHeaders().set(EncryptorConstant.TRACE_HEADER, UUID.randomUUID().toString());
                setStatusCode(status);
                return setComplete();
            }
        };
        // CEK 副本在全链终态（含 skip 透传/无 body/超限 fail/取消）一律清零；
        // 加密路径里 doFinally 的提前清零与这里重复 fill，幂等无害
        return chain.filter(exchange.mutate().response(decorated).build())
            .doFinally(signal -> {
                if (cek != null) {
                    java.util.Arrays.fill(cek, (byte) 0);
                }
            });
    }
}
