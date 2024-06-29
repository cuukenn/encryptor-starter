package io.github.cuukenn.encryptor.reactive.gateway.rewrite;

import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.converter.DataConverter;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyRequestBodyGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.core.Ordered;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author changgg
 */
public class EncryptorRequestFilter implements GlobalFilter, Ordered {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorRequestFilter.class);
    private final ModifyRequestBodyGatewayFilterFactory gatewayFilterFactory;
    private final int order;

    public EncryptorRequestFilter(ModifyRequestBodyGatewayFilterFactory gatewayFilterFactory, int order) {
        this.gatewayFilterFactory = gatewayFilterFactory;
        this.order = order;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!GatewayKit.isReqEncryptorEnable(exchange)) {
            return chain.filter(exchange);
        }
        ModifyRequestBodyGatewayFilterFactory.Config config = new ModifyRequestBodyGatewayFilterFactory.Config();
        config.setInClass(String.class);
        config.setOutClass(byte[].class);
        config.setRewriteFunction(new EncryptorDecoderFunction(GatewayKit.getEncryptorFacade(exchange), GatewayKit.getEncryptorDataConverter(exchange)));
        return this.gatewayFilterFactory.apply(config).filter(exchange, chain);
    }

    @Override
    public int getOrder() {
        return order;
    }

    /**
     * @author changgg
     */
    public static class EncryptorDecoderFunction implements RewriteFunction<String, byte[]> {
        private final EncryptorFacade encryptorEncoder;
        private final DataConverter reactiveDataConverter;

        public EncryptorDecoderFunction(EncryptorFacade encryptorEncoder, DataConverter reactiveDataConverter) {
            this.encryptorEncoder = encryptorEncoder;
            this.reactiveDataConverter = reactiveDataConverter;
        }

        @Override
        public Publisher<byte[]> apply(ServerWebExchange serverWebExchange, String data) {
            if (data == null) {
                return Mono.empty();
            }
            EncryptorDataWrapper dataWrapper = reactiveDataConverter.load(serverWebExchange.getRequest(), data);
            serverWebExchange.getAttributes().put(CoreEncryptorConstant.KEY, dataWrapper.getKey());
            return Mono.just(encryptorEncoder.decrypt(dataWrapper));
        }
    }
}
