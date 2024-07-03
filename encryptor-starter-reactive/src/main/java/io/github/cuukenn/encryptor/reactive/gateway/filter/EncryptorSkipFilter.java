package io.github.cuukenn.encryptor.reactive.gateway.filter;

import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author changgg
 */
public class EncryptorSkipFilter implements GlobalFilter, Ordered {
    @SuppressWarnings("UastIncorrectHttpHeaderInspection")
    private static final String SKIP_HEADER = "x-skip-encryptor";
    private final int order;

    public EncryptorSkipFilter(int order) {
        this.order = order;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String skip = exchange.getRequest().getHeaders().getFirst(SKIP_HEADER);
        if (skip != null) {
            exchange.getAttributes().remove(GatewayConstant.GATEWAY_ENCRYPTOR_ENABLE);
        }
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return order;
    }
}
