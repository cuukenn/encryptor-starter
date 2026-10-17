package io.github.cuukenn.encryptor.reactive.gateway.filter;

import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayContext;
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
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 网关请求过滤器：决策（skip/黑名单/bypass/ct 黑名单）+ 三载体识别 + 一次解密 + query/body 改写。
 * 密码学在专用有界执行器上执行（队列满/失败 → failure-status）。
 *
 * @author changgg
 */
public class EncryptorGatewayFilter implements GlobalFilter, Ordered {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorGatewayFilter.class);
    private static final byte[] EMPTY_BYTES = new byte[0];
    private static final Scheduler CRYPTO =
        Schedulers.newBoundedElastic(Runtime.getRuntime().availableProcessors(), 1000, "encryptor-crypto");

    private final GatewayEncryptorConfig config;
    private final EncryptorConfig reactiveConfig;
    private final DefaultProtocol protocol;

    public EncryptorGatewayFilter(GatewayEncryptorConfig config, EncryptorConfig reactiveConfig, DefaultProtocol protocol) {
        this.config = config;
        this.reactiveConfig = reactiveConfig;
        this.protocol = protocol;
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
        String uri = request.getURI().getPath();
        String method = request.getMethodValue();
        // 2. uri/method 黑名单透传
        if (StrKit.anyMatch(uri, config.getBlackUris())
            || (method != null && config.getBlackMethods().contains(method))) {
            return chain.filter(exchange);
        }
        // 3. 运行期旁路透传
        if (protocol.runtime().bypassRequest()) {
            return chain.filter(exchange);
        }
        // 4. 请求方向 content-type 黑名单透传（不请求解密 ⇒ 也不响应加密）
        MediaType contentType = request.getHeaders().getContentType();
        String contentTypeValue = contentType == null ? "" : contentType.toString();
        if (StrKit.anyMatch(contentTypeValue, config.getBlackReqContentType())) {
            return chain.filter(exchange);
        }
        // 5. 载体识别
        String compact = request.getQueryParams().getFirst(GatewayConstant.JWE_PARAM);
        if (compact != null) {
            return proceed(exchange, chain, compact, GatewayContext.Carrier.QUERY, uri, method);
        }
        if (contentType != null && MediaType.APPLICATION_JSON.isCompatibleWith(contentType)) {
            return readBody(exchange)
                .flatMap(bytes -> proceed(exchange, chain, jweFromJson(bytes), GatewayContext.Carrier.JSON, uri, method))
                .onErrorResume(EncryptorException.class, e -> fail(exchange, e))
                .onErrorResume(DataBufferLimitException.class, e -> fail(exchange, 413));
        }
        if (contentType != null && MediaType.APPLICATION_FORM_URLENCODED.isCompatibleWith(contentType)) {
            return readBody(exchange)
                .flatMap(bytes -> proceed(exchange, chain, jweFromForm(bytes), GatewayContext.Carrier.FORM, uri, method))
                .onErrorResume(EncryptorException.class, e -> fail(exchange, e))
                .onErrorResume(DataBufferLimitException.class, e -> fail(exchange, 413));
        }
        // 无载体：requireEncrypted ⇒ failure-status；否则透传
        if (reactiveConfig.isRequireEncrypted()) {
            return fail(exchange, reactiveConfig.getFailureStatus());
        }
        return chain.filter(exchange);
    }

    /** 解密 + uri 级 kid 白名单 + 上下文登记 + query/body 改写。 */
    private Mono<Void> proceed(ServerWebExchange exchange, GatewayFilterChain chain, String compact,
                               GatewayContext.Carrier carrier, String uri, String method) {
        if (compact == null || compact.isEmpty()) {
            if (reactiveConfig.isRequireEncrypted()) {
                return fail(exchange, reactiveConfig.getFailureStatus());
            }
            return chain.filter(exchange);
        }
        return Mono.fromCallable(() -> protocol.openRequest(compact, uri, method))
            .subscribeOn(CRYPTO)
            .flatMap(ctx -> {
                // 6. uri 级 kid 白名单（正则→允许 kid 集；空=全允许）
                String matched = StrKit.getBestMatchStr(uri, config.getCryptoConfig().keySet());
                if (matched != null) {
                    List<String> allowedKids = config.getCryptoConfig().get(matched);
                    if (allowedKids != null && !allowedKids.isEmpty() && !allowedKids.contains(ctx.kid())) {
                        logger.warn("kid not allowed for uri: {}, kid: {}", uri, ctx.kid());
                        return fail(exchange, reactiveConfig.getFailureStatus());
                    }
                }
                GatewayContext gatewayContext = new GatewayContext();
                gatewayContext.setCarrier(carrier);
                gatewayContext.setJweContext(ctx);
                gatewayContext.setPlaintextBody(ctx.plaintext());
                gatewayContext.setEncrypted(true);
                exchange.getAttributes().put(GatewayConstant.GATEWAY_CONTEXT_ATTR, gatewayContext);
                return chain.filter(exchange.mutate().request(decorate(exchange, ctx, carrier)).build());
            })
            .onErrorResume(EncryptorException.class, e -> {
                logger.warn("decrypt request failed, uri: {}, failure: {}", uri, e.failure());
                return fail(exchange, reactiveConfig.getFailureStatus());
            });
    }

    /** 把明文装回请求：QUERY 改 query 参数；JSON/FORM 换 body（明文即业务 body）。 */
    private ServerHttpRequest decorate(ServerWebExchange exchange, JweContext ctx, GatewayContext.Carrier carrier) {
        ServerHttpRequest request = exchange.getRequest();
        if (carrier == GatewayContext.Carrier.QUERY) {
            String plaintext = new String(ctx.plaintext(), StandardCharsets.UTF_8);
            MultiValueMap<String, String> queryParams = UriComponentsBuilder.newInstance()
                .query(plaintext).build().getQueryParams();
            return new ServerHttpRequestDecorator(request) {
                @Override
                public MultiValueMap<String, String> getQueryParams() {
                    return queryParams;
                }

                @Override
                public URI getURI() {
                    return UriComponentsBuilder.fromUri(request.getURI()).replaceQuery(plaintext).build(true).toUri();
                }
            };
        }
        byte[] plaintext = ctx.plaintext();
        return new ServerHttpRequestDecorator(request) {
            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.just(exchange.getResponse().bufferFactory().wrap(plaintext));
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
            return Mono.error(new EncryptorException(EncryptorFailure.TOO_LARGE,
                "请求体超过 max-request-size: " + contentLength));
        }
        return DataBufferUtils.join(exchange.getRequest().getBody())
            .map(buffer -> {
                byte[] bytes = new byte[buffer.readableByteCount()];
                buffer.read(bytes);
                DataBufferUtils.release(buffer);
                return bytes;
            })
            .defaultIfEmpty(EMPTY_BYTES)
            .flatMap(bytes -> {
                if (max > 0 && bytes.length > max) {
                    return Mono.error(new EncryptorException(EncryptorFailure.TOO_LARGE,
                        "请求体超过 max-request-size: " + bytes.length));
                }
                return Mono.just(bytes);
            });
    }

    private String jweFromJson(byte[] bytes) {
        if (bytes.length == 0) {
            return null;
        }
        return JSONUtil.parseObj(new String(bytes, StandardCharsets.UTF_8)).getStr(GatewayConstant.JWE_PARAM);
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

    private Mono<Void> fail(ServerWebExchange exchange, EncryptorException e) {
        int status = e.failure() == EncryptorFailure.TOO_LARGE ? 413 : reactiveConfig.getFailureStatus();
        return fail(exchange, status);
    }

    private Mono<Void> fail(ServerWebExchange exchange, int status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.valueOf(status));
        return response.setComplete();
    }
}
