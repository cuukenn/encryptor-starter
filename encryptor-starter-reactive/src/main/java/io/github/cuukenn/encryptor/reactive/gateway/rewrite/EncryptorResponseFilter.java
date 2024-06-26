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
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyResponseBodyGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 响应加密及签名
 *
 * @author changgg
 */
public class EncryptorResponseFilter implements GlobalFilter {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorResponseFilter.class);
    private final ModifyResponseBodyGatewayFilterFactory gatewayFilterFactory;

    public EncryptorResponseFilter(ModifyResponseBodyGatewayFilterFactory gatewayFilterFactory) {
        this.gatewayFilterFactory = gatewayFilterFactory;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!GatewayKit.isResEncryptorEnable(exchange)) {
            return chain.filter(exchange);
        }
        ModifyResponseBodyGatewayFilterFactory.Config config = new ModifyResponseBodyGatewayFilterFactory.Config();
        config.setInClass(EncryptorDataWrapper.class);
        config.setOutClass(String.class);
        config.setRewriteFunction(new EncryptorEncoderFunction(GatewayKit.getEncryptorFacade(exchange), GatewayKit.getEncryptorDataConverter(exchange)));
        return this.gatewayFilterFactory.apply(config).filter(exchange, chain);
    }

    /**
     * @author changgg
     */
    public static class EncryptorEncoderFunction implements RewriteFunction<byte[], String> {
        private final EncryptorFacade encryptorEncoder;
        private final DataConverter dataConverter;

        public EncryptorEncoderFunction(EncryptorFacade encryptorEncoder, DataConverter dataConverter) {
            this.encryptorEncoder = encryptorEncoder;
            this.dataConverter = dataConverter;
        }

        @Override
        public Publisher<String> apply(ServerWebExchange serverWebExchange, byte[] data) {
            if (data == null) {
                return Mono.empty();
            }
            String key = serverWebExchange.getAttribute(CoreEncryptorConstant.KEY);
            return Mono.just(dataConverter.post(serverWebExchange.getResponse(), encryptorEncoder.encrypt(data, key)));
        }
    }
}
