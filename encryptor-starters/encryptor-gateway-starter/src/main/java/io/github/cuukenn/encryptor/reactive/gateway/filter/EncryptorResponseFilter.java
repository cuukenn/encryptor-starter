package io.github.cuukenn.encryptor.reactive.gateway.filter;

import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayContext;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * 网关响应过滤器：仅对"本次请求成功解密"的流量加密回写（{@code {"jwe":"…"}}）。
 * 链后（组装响应时）判响应 content-type 黑名单；超 max-response-size ⇒ 500 不发明文。
 *
 * @author changgg
 */
public class EncryptorResponseFilter implements GlobalFilter, Ordered {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorResponseFilter.class);
    private static final Scheduler CRYPTO =
        Schedulers.newBoundedElastic(Runtime.getRuntime().availableProcessors(), 1000, "encryptor-crypto");

    private final GatewayEncryptorConfig config;
    private final EncryptorConfig reactiveConfig;
    private final DefaultProtocol protocol;

    public EncryptorResponseFilter(GatewayEncryptorConfig config, EncryptorConfig reactiveConfig, DefaultProtocol protocol) {
        this.config = config;
        this.reactiveConfig = reactiveConfig;
        this.protocol = protocol;
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
        ServerHttpResponseDecorator decorated = new ServerHttpResponseDecorator(response) {
            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                String resCt = getHeaders().getContentType() == null
                    ? "" : getHeaders().getContentType().toString();
                if (StrKit.anyMatch(resCt, config.getSkipResContentType())) {
                    return super.writeWith(body);
                }
                return DataBufferUtils.join(body)
                    .flatMap(buffer -> {
                        byte[] bytes = new byte[buffer.readableByteCount()];
                        buffer.read(bytes);
                        DataBufferUtils.release(buffer);
                        long max = reactiveConfig.getMaxResponseSize();
                        if (max > 0 && bytes.length > max) {
                            logger.error("响应体超过 max-response-size: {}, 不发明文, uri: {}",
                                bytes.length, exchange.getRequest().getURI().getPath());
                            return fail(HttpStatus.INTERNAL_SERVER_ERROR);
                        }
                        String uri = exchange.getRequest().getURI().getPath();
                        String method = exchange.getRequest().getMethodValue();
                        JweContext jweContext = ctx.getJweContext();
                        // 显式带上请求协商出的 enc（C2）：SM4-GCM 的 CEK 是 16B，按长度猜会封成 A128GCM
                        return Mono.fromCallable(() -> protocol.codec().encryptResponse(
                                bytes, jweContext.cek(), jweContext.enc(), uri, method,
                                System.currentTimeMillis(), UUID.randomUUID().toString()))
                            .subscribeOn(CRYPTO)
                            .flatMap(jwe -> {
                                byte[] payload = ("{\"jwe\":\"" + jwe + "\"}")
                                    .getBytes(StandardCharsets.UTF_8);
                                getHeaders().setContentType(MediaType.APPLICATION_JSON);
                                // body 已被换成 JWE JSON：下游若声明 Content-Encoding（如 gzip）必须去掉，
                                // 否则客户端按 gzip 解压 JWE JSON 得到乱码
                                getHeaders().remove(HttpHeaders.CONTENT_ENCODING);
                                getHeaders().setContentLength(payload.length);
                                return super.writeWith(Mono.just(getDelegate().bufferFactory().wrap(payload)));
                            })
                            .onErrorResume(Throwable.class, e -> {
                                logger.error("响应加密失败, uri: {}", uri, e);
                                return fail(HttpStatus.INTERNAL_SERVER_ERROR);
                            });
                    });
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
        return chain.filter(exchange.mutate().response(decorated).build());
    }
}
