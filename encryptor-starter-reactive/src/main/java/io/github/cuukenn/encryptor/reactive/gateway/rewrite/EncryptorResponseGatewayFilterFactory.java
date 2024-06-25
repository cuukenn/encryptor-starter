package io.github.cuukenn.encryptor.reactive.gateway.rewrite;

import io.github.cuukenn.encryptor.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.converter.DataConverter;
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
    private final EncryptorFacade encryptorEncoder;
    private final DataConverter dataConverter;

    public EncryptorResponseGatewayFilterFactory(List<HttpMessageReader<?>> messageReaders,
                                                 Set<MessageBodyDecoder> messageBodyDecoders, Set<MessageBodyEncoder> messageBodyEncoders,
                                                 EncryptorFacade encryptorEncoder, DataConverter dataConverter) {
        super(messageReaders, messageBodyDecoders, messageBodyEncoders);
        this.encryptorEncoder = encryptorEncoder;
        this.dataConverter = dataConverter;
    }


    @Override
    public GatewayFilter apply(Config config) {
        return super.apply(getConfig());
    }

    protected Config getConfig() {
        Config config = new Config();
        config.setInClass(EncryptorDataWrapper.class);
        config.setOutClass(String.class);
        config.setRewriteFunction(new EncryptorEncoderFunction(encryptorEncoder, dataConverter));
        return config;
    }

    /**
     * @author changgg
     */
    public static class EncryptorEncoderFunction implements RewriteFunction<String, String> {
        private final EncryptorFacade encryptorEncoder;
        private final DataConverter dataConverter;

        public EncryptorEncoderFunction(EncryptorFacade encryptorEncoder, DataConverter dataConverter) {
            this.encryptorEncoder = encryptorEncoder;
            this.dataConverter = dataConverter;
        }

        @Override
        public Publisher<String> apply(ServerWebExchange serverWebExchange, String data) {
            if (data == null) {
                return Mono.empty();
            }
            String key = serverWebExchange.getAttribute(EncryptorConstant.KEY);
            return Mono.just(dataConverter.post(serverWebExchange.getResponse(), encryptorEncoder.encrypt(data, key)));
        }
    }
}
