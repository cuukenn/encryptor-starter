package io.github.cuukenn.encryptor.reactive.gateway.filter;

import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
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
                if (StrKit.anyMatch(resCt, config.getBlackResContentType())) {
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
                            setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                            return setComplete();
                        }
                        String uri = exchange.getRequest().getURI().getPath();
                        String method = exchange.getRequest().getMethodValue();
                        JweContext jweContext = ctx.getJweContext();
                        return Mono.fromCallable(() -> protocol.codec().encryptResponse(
                                bytes, jweContext.cek(), uri, method,
                                System.currentTimeMillis(), UUID.randomUUID().toString()))
                            .subscribeOn(CRYPTO)
                            .flatMap(jwe -> {
                                byte[] payload = ("{\"jwe\":\"" + jwe + "\"}")
                                    .getBytes(StandardCharsets.UTF_8);
                                getHeaders().setContentType(MediaType.APPLICATION_JSON);
                                getHeaders().setContentLength(payload.length);
                                return super.writeWith(Mono.just(getDelegate().bufferFactory().wrap(payload)));
                            });
                    });
            }
        };
        return chain.filter(exchange.mutate().response(decorated).build());
    }
}
