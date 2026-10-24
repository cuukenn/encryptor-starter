package io.github.cuukenn.encryptor.reactive.gateway.filter;

import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.JweCodec;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayContext;
import io.github.cuukenn.encryptor.reactive.gateway.runtime.CryptoExecutor;
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
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.RejectedExecutionException;

/**
 * 网关请求过滤器：决策（skip/黑名单/bypass/ct 黑名单）+ 三载体识别 + 一次解密 + query/body 改写。
 * 密码学在共用的有界执行器（{@link CryptoExecutor}）上执行（队列满 → 503，其余失败 → failure-status）。
 *
 * @author changgg
 */
public class EncryptorGatewayFilter implements GlobalFilter, Ordered {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorGatewayFilter.class);
    private static final byte[] EMPTY_BYTES = new byte[0];

    private final GatewayEncryptorConfig config;
    private final EncryptorConfig reactiveConfig;
    private final DefaultProtocol protocol;
    private final CryptoExecutor crypto;

    public EncryptorGatewayFilter(GatewayEncryptorConfig config, EncryptorConfig reactiveConfig,
                                  DefaultProtocol protocol, CryptoExecutor crypto) {
        this.config = config;
        this.reactiveConfig = reactiveConfig;
        this.protocol = protocol;
        this.crypto = crypto;
        logSkipSummary();
    }


    /** 启动期把四条名单与流式风险打到日志：默认名单/覆盖名单都能一眼看到。 */
    private void logSkipSummary() {
        logger.info("加密过滤名单: skip-uris={}, skip-methods={}, skip-req-content-type={}, skip-res-content-type={}",
            config.getSkipUris(), config.getSkipMethods(), config.getSkipReqContentType(), config.getSkipResContentType());
        boolean eventStream = false;
        for (String type : config.getSkipResContentType()) {
            if (type != null && type.toLowerCase(java.util.Locale.ROOT).contains("text/event-stream")) {
                eventStream = true;
                break;
            }
        }
        if (eventStream) {
            logger.warn("skip-res-content-type 含 text/event-stream：SSE 响应将不加密，直接明文输出");
        } else if (config.getSkipResContentType().isEmpty() && reactiveConfig.getMaxResponseSize() > 0) {
            logger.warn("skip-res-content-type 为空且 max-response-size={}：流式/大响应会被整体缓冲，超限返回失败",
                reactiveConfig.getMaxResponseSize());
        }
    }

    @Override
    public int getOrder() {
        return config.getFilterConfig().getEncryptorFilterOrder();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        // 1. skip 透传（运维口子：内网/共享密钥，启动有告警）
        if (config.isSkipAble() && request.getHeaders().containsKey(GatewayConstant.SKIP_HEADER)) {
            return chain.filter(exchange);
        }
        // AAD 口径与 servlet 侧一致：走 ContextAad.canonicalPath 归一（空路径归 "/"、统一解码形态）。
        // 网关没有 contextPath，传 null；不归一的话同一客户端报文在边界路径下会 AAD 不匹配。
        String uri = ContextAad.canonicalPath(request.getURI().getPath(), null);
        String method = request.getMethodValue();
        // 2. uri/method 黑名单透传（与 servlet 侧同一语义：整串正则匹配）
        // method 按规范大写归一后再匹配：配置写 get/Get/GET 都能命中
        if (StrKit.anyMatch(uri, config.getSkipUris()) || StrKit.anyMatch(method.toUpperCase(Locale.ROOT), config.getSkipMethods())) {
            return chain.filter(exchange);
        }
        // 3. 运行期旁路透传
        if (protocol.runtime().bypassRequest()) {
            return chain.filter(exchange);
        }
        // 4. 请求方向 content-type 黑名单透传（不请求解密 ⇒ 也不响应加密）
        MediaType contentType = request.getHeaders().getContentType();
        String contentTypeValue = contentType == null ? "" : contentType.toString().toLowerCase(Locale.ROOT);
        if (StrKit.anyMatch(contentTypeValue, config.getSkipReqContentType())) {
            return chain.filter(exchange);
        }
        // 5. 载体识别
        String compact = request.getQueryParams().getFirst(GatewayConstant.JWE_PARAM);
        if (compact != null) {
            return proceed(exchange, chain, compact, GatewayContext.Carrier.QUERY, uri, method, null);
        }
        if (isJson(contentType)) {
            return readBody(exchange)
                .flatMap(bytes -> proceed(exchange, chain, jweFromJson(bytes), GatewayContext.Carrier.JSON, uri, method, bytes))
                .onErrorResume(EncryptorException.class, e -> fail(exchange, e))
                .onErrorResume(DataBufferLimitException.class, e -> fail(exchange, 413, EncryptorFailure.TOO_LARGE, e));
        }
        if (contentType != null && MediaType.APPLICATION_FORM_URLENCODED.isCompatibleWith(contentType)) {
            return readBody(exchange)
                .flatMap(bytes -> proceed(exchange, chain, jweFromForm(bytes), GatewayContext.Carrier.FORM, uri, method, bytes))
                .onErrorResume(EncryptorException.class, e -> fail(exchange, e))
                .onErrorResume(DataBufferLimitException.class, e -> fail(exchange, 413, EncryptorFailure.TOO_LARGE, e));
        }
        // 无载体：requireEncrypted ⇒ failure-status；否则透传
        if (reactiveConfig.isRequireEncrypted()) {
            return fail(exchange, reactiveConfig.getFailureStatus(), EncryptorFailure.MISSING,
                JweCodec.fail(EncryptorFailure.MISSING, "命中加密范围但缺少 jwe 载体"));
        }
        return chain.filter(exchange);
    }

    /** 解密 + uri 级 kid 白名单 + 上下文登记 + query/body 改写。 */
    private Mono<Void> proceed(ServerWebExchange exchange, GatewayFilterChain chain, String compact,
                               GatewayContext.Carrier carrier, String uri, String method, byte[] cachedBody) {
        if (compact == null || compact.isEmpty()) {
            if (reactiveConfig.isRequireEncrypted()) {
                return fail(exchange, reactiveConfig.getFailureStatus(), EncryptorFailure.MISSING,
                    JweCodec.fail(EncryptorFailure.MISSING, "命中加密范围但缺少 jwe 载体"));
            }
            // JSON/form 分支已经读过 body；透传时必须回放，否则下游看到的是空流
            return chain.filter(cachedBody == null ? exchange : withCachedBody(exchange, cachedBody));
        }
        return Mono.fromCallable(() -> protocol.openRequest(compact, uri, method))
            .subscribeOn(crypto.scheduler())
            .flatMap(ctx -> {
                // 6. uri 级 kid 白名单（正则→允许 kid 集；空=全允许）
                String matched = StrKit.getBestMatchStr(uri, config.getCryptoConfig().keySet());
                if (matched != null) {
                    List<String> allowedKids = config.getCryptoConfig().get(matched);
                    if (allowedKids != null && !allowedKids.isEmpty() && !allowedKids.contains(ctx.kid())) {
                        logger.warn("kid not allowed for uri: {}, kid: {}", uri, ctx.kid());
                        ctx.destroy();
                        return fail(exchange, reactiveConfig.getFailureStatus(), EncryptorFailure.ALG_NOT_ALLOWED,
                            JweCodec.fail(EncryptorFailure.ALG_NOT_ALLOWED,
                                "uri=" + uri + " 的 kid 白名单不含: " + ctx.kid()));
                    }
                }
                GatewayContext gatewayContext = new GatewayContext();
                gatewayContext.setCarrier(carrier);
                gatewayContext.setJweContext(ctx);
                gatewayContext.setPlaintextBody(ctx.plaintext());
                gatewayContext.setEncrypted(true);
                exchange.getAttributes().put(GatewayConstant.GATEWAY_CONTEXT_ATTR, gatewayContext);
                // 响应过滤器在链内完成回加密；链终止（成功/失败/取消）后再清零 CEK/明文
                return chain.filter(exchange.mutate().request(decorate(exchange, ctx, carrier)).build())
                    .doFinally(signal -> cleanup(exchange));
            })
            .onErrorResume(EncryptorException.class, e -> {
                logger.warn("decrypt request failed, uri: {}, failure: {}", uri, e.failure());
                return fail(exchange, reactiveConfig.getFailureStatus());
            })
            .onErrorResume(RejectedExecutionException.class, e -> {
                // 共用密码学执行器队列已满：服务端过载，不能把 5xx 伪装成客户端错误（503 可重试）
                logger.error("crypto executor rejected task, uri: {}", uri, e);
                return fail(exchange, HttpStatus.SERVICE_UNAVAILABLE.value(), EncryptorFailure.INTERNAL, e);
            });
    }

    /** 把已缓存的请求体装回 exchange，供 require-encrypted=false 的明文请求继续下行。 */
    private ServerWebExchange withCachedBody(ServerWebExchange exchange, byte[] body) {
        ServerHttpRequest request = new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.defer(() -> Flux.just(exchange.getResponse().bufferFactory().wrap(body)));
            }

            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders headers = new HttpHeaders();
                headers.putAll(exchange.getRequest().getHeaders());
                headers.setContentLength(body.length);
                return headers;
            }
        };
        return exchange.mutate().request(request).build();
    }

    /** 把明文装回请求：QUERY 改 query 参数；JSON/FORM 换 body（明文即业务 body）。 */
    private ServerHttpRequest decorate(ServerWebExchange exchange, JweContext ctx, GatewayContext.Carrier carrier) {
        ServerHttpRequest request = exchange.getRequest();
        if (carrier == GatewayContext.Carrier.QUERY) {
            String plaintext = new String(ctx.plaintext(), StandardCharsets.UTF_8);
            // 契约：QUERY 载体明文是 form 语义的 urlencoded 文本（与 servlet 侧 parseQuery 的
            // URLDecoder 同一口径，空格编码为 +），且明文即完整 query——jwe 之外的原始 query 参数
            // 以明文为准，不在明文里的参数会被丢弃。这里按 form 语义解出参数，再以 URI 形态
            // （空格=%20、字面 + 编码为 %2B）重建 query，消除两侧对 '+' 的解码口径分叉。
            MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
            StringBuilder encoded = new StringBuilder(plaintext.length());
            for (String pair : plaintext.split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int eq = pair.indexOf('=');
                String name;
                String value;
                try {
                    name = java.net.URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), "UTF-8");
                    value = java.net.URLDecoder.decode(eq < 0 ? "" : pair.substring(eq + 1), "UTF-8");
                } catch (Exception e) {
                    // 与 servlet parseQuery 同口径：非法 urlencoded 文本按失败面拒绝
                    throw audit(EncryptorFailure.INTERNAL,
                        "query 明文不是合法的 urlencoded 文本: " + e.getMessage());
                }
                queryParams.add(name, value);
                if (encoded.length() > 0) {
                    encoded.append('&');
                }
                encoded.append(uriEncode(name)).append('=').append(uriEncode(value));
            }
            // 提前校验重建结果：非法编码转成 failure-status，不能留到下游 getURI() 时炸成 500
            URI targetUri;
            try {
                targetUri = UriComponentsBuilder.fromUri(request.getURI()).replaceQuery(encoded.toString()).build(true).toUri();
            } catch (IllegalArgumentException e) {
                throw audit(EncryptorFailure.INTERNAL,
                    "query 明文重建后不是合法的已编码 query: " + e.getMessage());
            }
            return new ServerHttpRequestDecorator(request) {
                @Override
                public MultiValueMap<String, String> getQueryParams() {
                    return queryParams;
                }

                @Override
                public URI getURI() {
                    return targetUri;
                }
            };
        }
        // 克隆明文：doFinally 清理会原地清零原数组，下游（Retry/重路由）在清理后二次订阅
        // getBody() 时会静默发出全零 body（响应侧 cek.clone() 同款规避）
        byte[] plaintext = ctx.plaintext().clone();
        return new ServerHttpRequestDecorator(request) {
            @Override
            public Flux<DataBuffer> getBody() {
                // 每次订阅都要新建 DataBuffer：Retry 等过滤器会二次订阅同一 Flux
                return Flux.defer(() -> Flux.just(exchange.getResponse().bufferFactory().wrap(plaintext)));
            }

            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders headers = new HttpHeaders();
                headers.putAll(request.getHeaders());
                headers.remove(HttpHeaders.CONTENT_LENGTH);
                return headers;
            }
        };
    }

    /** 有界读请求体：Content-Length 或实际长度超过 max-request-size ⇒ TOO_LARGE（→413）。 */
    private Mono<byte[]> readBody(ServerWebExchange exchange) {
        long max = reactiveConfig.getMaxRequestSize();
        long contentLength = exchange.getRequest().getHeaders().getContentLength();
        if (max > 0 && contentLength > max) {
            return Mono.error(audit(EncryptorFailure.TOO_LARGE,
                "请求体超过 max-request-size: " + contentLength));
        }
        // 必须在读取过程中限长：chunked 请求没有 Content-Length，先 join 再判长度会把整个 body 拼进堆
        int joinLimit = max > 0 ? (int) Math.min(max, Integer.MAX_VALUE) : -1;
        return DataBufferUtils.join(exchange.getRequest().getBody(), joinLimit)
            .map(buffer -> {
                byte[] bytes = new byte[buffer.readableByteCount()];
                buffer.read(bytes);
                DataBufferUtils.release(buffer);
                return bytes;
            })
            .defaultIfEmpty(EMPTY_BYTES)
            .flatMap(bytes -> {
                if (max > 0 && bytes.length > max) {
                    return Mono.error(audit(EncryptorFailure.TOO_LARGE,
                        "请求体超过 max-request-size: " + bytes.length));
                }
                return Mono.just(bytes);
            });
    }

    /** URL 编码为 URI query 形态：URLEncoder 的 '+'（空格）改写为 %20，与 build(true) 的已编码口径一致。 */
    private static String uriEncode(String value) {
        try {
            return java.net.URLEncoder.encode(value, "UTF-8").replace("+", "%20");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 必然存在", e);
        }
    }

    private String jweFromJson(byte[] bytes) {
        if (bytes.length == 0) {
            return null;
        }
        try {
            return JSONUtil.parseObj(new String(bytes, StandardCharsets.UTF_8)).getStr(GatewayConstant.JWE_PARAM);
        } catch (RuntimeException e) {
            // 非法 JSON 信封：与 servlet 侧一致按 failure-status 处理，不能让 JSONException 冒泡成 500
            throw audit(EncryptorFailure.BAD_HEADER, "request body is not a valid json envelope");
        }
    }

    private String jweFromForm(byte[] bytes) {
        if (bytes.length == 0) {
            return null;
        }
        String body = new String(bytes, StandardCharsets.UTF_8);
        String prefix = GatewayConstant.JWE_PARAM + "=";
        for (String field : body.split("&")) {
            if (field.startsWith(prefix)) {
                try {
                    return java.net.URLDecoder.decode(field.substring(prefix.length()), "UTF-8");
                } catch (Exception e) {
                    return null;
                }
            }
        }
        return null;
    }

    /** codec 抛出的异常已经审计过；构造期经 {@link #audit} 的异常也已审计——这里只负责响应面。 */
    private Mono<Void> fail(ServerWebExchange exchange, EncryptorException e) {
        int status = e.failure() == EncryptorFailure.TOO_LARGE ? 413 : reactiveConfig.getFailureStatus();
        return respond(exchange, status);
    }

    private Mono<Void> fail(ServerWebExchange exchange, int status) {
        return respond(exchange, status);
    }

    /** codec 之外的失败分支（缺载体/kid 白名单/执行器拒绝/超限）的唯一审计出口。 */
    private Mono<Void> fail(ServerWebExchange exchange, int status, EncryptorFailure failure, Throwable cause) {
        protocol.listener().onDecryptFailure(failure, cause);
        return respond(exchange, status);
    }

    /** 构造 codec 之外的失败异常并立即审计（失败分支的异常在构造期即审计，避免经 fail(e) 双重计数）。 */
    private EncryptorException audit(EncryptorFailure failure, String message) {
        EncryptorException e = JweCodec.fail(failure, message);
        protocol.listener().onDecryptFailure(failure, e);
        return e;
    }

    private Mono<Void> respond(ServerWebExchange exchange, int status) {
        cleanup(exchange);
        ServerHttpResponse response = exchange.getResponse();
        String trace = UUID.randomUUID().toString();
        // 响应头与日志必须同值：客户端拿 trace 来排障时能在日志里 grep 到
        logger.warn("encrypt request failed, trace: {}, status: {}, {} {}", trace, status,
            exchange.getRequest().getMethod().name(), exchange.getRequest().getURI().getPath());
        response.getHeaders().set(EncryptorConstant.TRACE_HEADER, trace);
        response.setStatusCode(HttpStatus.valueOf(status));
        return response.setComplete();
    }

    /** JSON 载体：application/json 及其结构化后缀（application/vnd.api+json 等）。 */
    private static boolean isJson(MediaType contentType) {
        return contentType != null
            && (MediaType.APPLICATION_JSON.isCompatibleWith(contentType) || contentType.getSubtype().endsWith("+json"));
    }

    /** 清掉 exchange 上的请求上下文并 best-effort 清零明文/CEK。 */
    private static void cleanup(ServerWebExchange exchange) {
        Object value = exchange.getAttributes().remove(GatewayConstant.GATEWAY_CONTEXT_ATTR);
        if (value instanceof GatewayContext) {
            ((GatewayContext) value).destroy();
        }
    }
}
