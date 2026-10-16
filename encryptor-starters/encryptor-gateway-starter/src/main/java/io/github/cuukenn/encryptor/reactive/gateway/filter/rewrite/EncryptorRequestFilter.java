package io.github.cuukenn.encryptor.reactive.gateway.filter.rewrite;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.reactive.gateway.converter.DefaultMessageConverter;
import io.github.cuukenn.encryptor.reactive.gateway.converter.MessageReader;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyRequestBodyGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.core.ResolvableType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * @author changgg
 */
public class EncryptorRequestFilter implements GlobalFilter, Ordered {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorRequestFilter.class);
    private final ModifyRequestBodyGatewayFilterFactory gatewayFilterFactory;
    private final List<MessageReader<?, ?>> messageReaders;
    private final int order;

    public EncryptorRequestFilter(ModifyRequestBodyGatewayFilterFactory gatewayFilterFactory, List<MessageReader<?, ?>> messageReaders, int order) {
        this.gatewayFilterFactory = gatewayFilterFactory;
        this.messageReaders = messageReaders;
        this.order = order;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!GatewayKit.isReqEncryptorEnable(exchange)) {
            return chain.filter(exchange);
        }
        MessageReader<?, ?> messageReader = messageReaders.stream().filter(reader -> reader.canRead(exchange.getRequest().getHeaders().getContentType()))
                .findFirst()
                .orElseGet(DefaultMessageConverter::new);
        ResolvableType resolvableType = Arrays.stream(ResolvableType.forClass(messageReader.getClass())
                        .getInterfaces()).filter(x -> Objects.requireNonNull(x.resolve()).isAssignableFrom(MessageReader.class))
                .findFirst().orElseThrow(() -> new EncryptorException("Get ResolvableType Error"));
        ModifyRequestBodyGatewayFilterFactory.Config config = new ModifyRequestBodyGatewayFilterFactory.Config();
        config.setInClass(resolvableType.getGeneric(0).toClass());
        config.setOutClass(resolvableType.getGeneric(1).toClass());
        config.setRewriteFunction(messageReader.read());
        // 请求体解密发生在 rewrite 里（反应式）：报错必须以 4xx 收敛，不能让它变成 500
        return this.gatewayFilterFactory.apply(config).filter(exchange, chain)
                .onErrorResume(EncryptorException.class, e -> GatewayKit.failure(exchange));
    }

    @Override
    public int getOrder() {
        return order;
    }
}
