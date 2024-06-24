package com.github.cuukenn.demo.encrypt.lectotype.gateway.rewrite;

import com.github.cuukenn.demo.encrypt.lectotype.configuration.EncryptorReactiveAutoConfiguration;
import com.github.cuukenn.demo.encrypt.lectotype.core.CheckerStrategy;
import com.github.cuukenn.demo.encrypt.lectotype.core.encoder.EncryptorEncoder;
import com.github.cuukenn.demo.encrypt.lectotype.core.encoder.SignerEncoder;
import com.github.cuukenn.demo.encrypt.lectotype.kit.EncryptorKit;
import com.github.cuukenn.demo.encrypt.lectotype.pojo.EncryptorDataWrapper;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyRequestBodyGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * @author changgg
 */
public class EncryptorRequestGatewayFilterFactory extends ModifyRequestBodyGatewayFilterFactory {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorRequestGatewayFilterFactory.class);
    private final EncryptorEncoder encryptorEncoder;
    private final SignerEncoder signerEncoder;
    private final List<CheckerStrategy> checkerStrategies;

    public EncryptorRequestGatewayFilterFactory(EncryptorEncoder encryptorEncoder, SignerEncoder signerEncoder, List<CheckerStrategy> checkerStrategies) {
        this.encryptorEncoder = encryptorEncoder;
        this.signerEncoder = signerEncoder;
        this.checkerStrategies = checkerStrategies;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return super.apply(getConfig());
    }

    protected Config getConfig() {
        Config config = new Config();
        config.setInClass(String.class);
        config.setOutClass(EncryptorDataWrapper.class);
        config.setRewriteFunction(new EncryptorDecoderFunction(encryptorEncoder, signerEncoder, checkerStrategies));
        return config;
    }

    /**
     * @author changgg
     */
    public static class EncryptorDecoderFunction implements RewriteFunction<EncryptorDataWrapper, String> {
        private final EncryptorEncoder encryptorEncoder;
        private final SignerEncoder signerEncoder;
        private final List<CheckerStrategy> checkerStrategies;

        public EncryptorDecoderFunction(EncryptorEncoder encryptorEncoder, SignerEncoder signerEncoder, List<CheckerStrategy> checkerStrategies) {
            this.encryptorEncoder = encryptorEncoder;
            this.signerEncoder = signerEncoder;
            this.checkerStrategies = checkerStrategies;
        }

        @Override
        public Publisher<String> apply(ServerWebExchange serverWebExchange, EncryptorDataWrapper data) {
            return Mono.just(EncryptorKit.decrypt(encryptorEncoder, signerEncoder, checkerStrategies, data));
        }
    }
}
