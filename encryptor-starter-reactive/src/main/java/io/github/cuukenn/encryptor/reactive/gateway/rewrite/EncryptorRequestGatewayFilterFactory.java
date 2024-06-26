package io.github.cuukenn.encryptor.reactive.gateway.rewrite;

import io.github.cuukenn.encryptor.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.converter.DataConverter;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyRequestBodyGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author changgg
 */
public class EncryptorRequestGatewayFilterFactory extends ModifyRequestBodyGatewayFilterFactory {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorRequestGatewayFilterFactory.class);
    private final EncryptorFacade encryptorEncoder;
    private final DataConverter dataConverter;

    public EncryptorRequestGatewayFilterFactory(EncryptorFacade encryptorEncoder, DataConverter dataConverter) {
        this.encryptorEncoder = encryptorEncoder;
        this.dataConverter = dataConverter;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return super.apply(getConfig());
    }

    protected Config getConfig() {
        Config config = new Config();
        config.setInClass(String.class);
        config.setOutClass(byte[].class);
        config.setRewriteFunction(new EncryptorDecoderFunction(encryptorEncoder, dataConverter));
        return config;
    }

    /**
     * @author changgg
     */
    public static class EncryptorDecoderFunction implements RewriteFunction<String, byte[]> {
        private final EncryptorFacade encryptorEncoder;
        private final DataConverter dataConverter;

        public EncryptorDecoderFunction(EncryptorFacade encryptorEncoder, DataConverter dataConverter) {
            this.encryptorEncoder = encryptorEncoder;
            this.dataConverter = dataConverter;
        }

        @Override
        public Publisher<byte[]> apply(ServerWebExchange serverWebExchange, String data) {
            if (data == null) {
                return null;
            }
            EncryptorDataWrapper dataWrapper = dataConverter.load(serverWebExchange.getRequest(), data);
            serverWebExchange.getAttributes().put(EncryptorConstant.KEY, dataWrapper.getKey());
            return Mono.just(encryptorEncoder.decrypt(dataWrapper));
        }
    }
}
