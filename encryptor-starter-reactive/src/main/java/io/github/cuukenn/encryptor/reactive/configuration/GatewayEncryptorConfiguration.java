package io.github.cuukenn.encryptor.reactive.configuration;

import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.converter.DataConverter;
import io.github.cuukenn.encryptor.reactive.gateway.rewrite.EncryptorRequestGatewayFilterFactory;
import io.github.cuukenn.encryptor.reactive.gateway.rewrite.EncryptorRequestParameterGatewayFilterFactory;
import io.github.cuukenn.encryptor.reactive.gateway.rewrite.EncryptorResponseGatewayFilterFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.MessageBodyDecoder;
import org.springframework.cloud.gateway.filter.factory.rewrite.MessageBodyEncoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.codec.HttpMessageReader;

import java.util.List;
import java.util.Set;

/**
 * @author changgg
 */
@Configuration
@ConditionalOnProperty(prefix = EncryptorConfig.PREFIX + ".gateway", name = "enable", havingValue = "true", matchIfMissing = true)
public class GatewayEncryptorConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorReactiveAutoConfiguration.class);

    @ConditionalOnClass(GatewayFilterFactory.class)
    @ConditionalOnBean(value = {EncryptorEncoder.class, SignerEncoder.class})
    @ConditionalOnMissingBean(name = "defaultRequestParameterEncryptorFilter")
    @Bean("defaultRequestParameterEncryptorFilter")
    public EncryptorRequestParameterGatewayFilterFactory encryptorRequestParameterGatewayFilterFactory(EncryptorFacade encryptorEncoder, DataConverter dataConverter) {
        logger.info("register request parameter encryptor");
        return new EncryptorRequestParameterGatewayFilterFactory(encryptorEncoder, dataConverter);
    }

    @ConditionalOnClass(GatewayFilterFactory.class)
    @ConditionalOnMissingBean(name = "defaultResponseBodyEncryptorFilter")
    @ConditionalOnBean(value = {EncryptorEncoder.class, SignerEncoder.class})
    @Bean("defaultResponseBodyEncryptorFilter")
    public EncryptorRequestGatewayFilterFactory encryptorRequestGatewayFilterFactory(EncryptorFacade encryptorEncoder, DataConverter dataConverter) {
        logger.info("register request body encryptor");
        return new EncryptorRequestGatewayFilterFactory(encryptorEncoder, dataConverter);
    }

    @ConditionalOnClass(GatewayFilterFactory.class)
    @ConditionalOnBean(value = {EncryptorEncoder.class, SignerEncoder.class})
    @ConditionalOnMissingBean(name = "defaultResponseEncryptorFilter")
    @Bean("defaultResponseEncryptorFilter")
    public EncryptorResponseGatewayFilterFactory encryptorResponseGatewayFilterFactory(List<HttpMessageReader<?>> messageReaders, Set<MessageBodyDecoder> messageBodyDecoders, Set<MessageBodyEncoder> messageBodyEncoders, EncryptorFacade encryptorEncoder, DataConverter dataConverter) {
        logger.info("register response encryptor");
        return new EncryptorResponseGatewayFilterFactory(messageReaders, messageBodyDecoders, messageBodyEncoders, encryptorEncoder, dataConverter);
    }
}
