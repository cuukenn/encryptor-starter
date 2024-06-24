package com.github.cuukenn.demo.encrypt.lectotype.gateway.rewrite;

import com.github.cuukenn.demo.encrypt.lectotype.core.encoder.EncryptorEncoder;
import com.github.cuukenn.demo.encrypt.lectotype.core.encoder.SignerEncoder;
import com.github.cuukenn.demo.encrypt.lectotype.kit.EncryptorKit;
import com.github.cuukenn.demo.encrypt.lectotype.pojo.EncryptorDataWrapper;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.rewrite.MessageBodyDecoder;
import org.springframework.cloud.gateway.filter.factory.rewrite.MessageBodyEncoder;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyResponseBodyGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.http.codec.HttpMessageReader;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Set;

/**
 * 响应加密及签名
 *
 * @author changgg
 */
public class EncryptorResponseGatewayFilterFactory extends ModifyResponseBodyGatewayFilterFactory {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorRequestGatewayFilterFactory.class);
    private final EncryptorEncoder encryptorEncoder;
    private final SignerEncoder signerEncoder;

    public EncryptorResponseGatewayFilterFactory(List<HttpMessageReader<?>> messageReaders,
                                                 Set<MessageBodyDecoder> messageBodyDecoders, Set<MessageBodyEncoder> messageBodyEncoders,
                                                 EncryptorEncoder encryptorEncoder, SignerEncoder signerEncoder) {
        super(messageReaders, messageBodyDecoders, messageBodyEncoders);
        this.encryptorEncoder = encryptorEncoder;
        this.signerEncoder = signerEncoder;
    }


    @Override
    public GatewayFilter apply(Config config) {
        return super.apply(getConfig());
    }

    protected Config getConfig() {
        Config config = new Config();
        config.setInClass(EncryptorDataWrapper.class);
        config.setOutClass(String.class);
        config.setRewriteFunction(new EncryptorEncoderFunction(encryptorEncoder, signerEncoder));
        return config;
    }

    /**
     * @author changgg
     */
    public static class EncryptorEncoderFunction implements RewriteFunction<String, EncryptorDataWrapper> {
        private final EncryptorEncoder encryptorEncoder;
        private final SignerEncoder signerEncoder;

        public EncryptorEncoderFunction(EncryptorEncoder encryptorEncoder, SignerEncoder signerEncoder) {
            this.encryptorEncoder = encryptorEncoder;
            this.signerEncoder = signerEncoder;
        }

        @Override
        public Publisher<EncryptorDataWrapper> apply(ServerWebExchange serverWebExchange, String data) {
            return Mono.just(EncryptorKit.encrypt(encryptorEncoder, signerEncoder, data));
        }
    }
}
