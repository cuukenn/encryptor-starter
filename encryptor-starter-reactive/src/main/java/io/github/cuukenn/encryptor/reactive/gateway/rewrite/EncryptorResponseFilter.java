package io.github.cuukenn.encryptor.reactive.gateway.rewrite;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.reactive.gateway.converter.DefaultMessageConverter;
import io.github.cuukenn.encryptor.reactive.gateway.converter.MessageWriter;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyResponseBodyGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.core.ResolvableType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * 响应加密及签名
 *
 * @author changgg
 */
public class EncryptorResponseFilter implements GlobalFilter, Ordered {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorResponseFilter.class);
    private final ModifyResponseBodyGatewayFilterFactory gatewayFilterFactory;
    private final List<MessageWriter<?, ?>> messageWriters;
    private final int order;

    public EncryptorResponseFilter(ModifyResponseBodyGatewayFilterFactory gatewayFilterFactory, List<MessageWriter<?, ?>> messageWriters, int order) {
        this.gatewayFilterFactory = gatewayFilterFactory;
        this.messageWriters = messageWriters;
        this.order = order;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!GatewayKit.isResEncryptorEnable(exchange)) {
            return chain.filter(exchange);
        }
        MessageWriter<?, ?> messageWriter = messageWriters.stream().filter(writer -> writer.canWrite(exchange.getResponse().getHeaders().getContentType()))
                .findFirst()
                .orElseGet(DefaultMessageConverter::new);
        ResolvableType resolvableType = Arrays.stream(ResolvableType.forClass(messageWriter.getClass())
                        .getInterfaces()).filter(x -> Objects.requireNonNull(x.resolve()).isAssignableFrom(MessageWriter.class))
                .findFirst().orElseThrow(() -> new EncryptorException("Get ResolvableType Error"));
        ModifyResponseBodyGatewayFilterFactory.Config config = new ModifyResponseBodyGatewayFilterFactory.Config();
        config.setInClass(resolvableType.getGeneric(0).toClass());
        config.setOutClass(resolvableType.getGeneric(1).toClass());
        config.setRewriteFunction(messageWriter.write());
        return this.gatewayFilterFactory.apply(config).filter(exchange, chain);
    }

    @Override
    public int getOrder() {
        return order;
    }
}
