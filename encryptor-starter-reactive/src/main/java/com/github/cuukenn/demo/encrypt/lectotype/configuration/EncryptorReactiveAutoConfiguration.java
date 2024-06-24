package com.github.cuukenn.demo.encrypt.lectotype.configuration;

import com.github.cuukenn.demo.encrypt.lectotype.config.EncryptorConfig;
import com.github.cuukenn.demo.encrypt.lectotype.core.CheckerStrategy;
import com.github.cuukenn.demo.encrypt.lectotype.core.checker.InMemoryNonceChecker;
import com.github.cuukenn.demo.encrypt.lectotype.core.checker.InRedisNonceChecker;
import com.github.cuukenn.demo.encrypt.lectotype.core.encoder.EncryptorEncoder;
import com.github.cuukenn.demo.encrypt.lectotype.core.encoder.SignerEncoder;
import com.github.cuukenn.demo.encrypt.lectotype.gateway.rewrite.EncryptorRequestGatewayFilterFactory;
import com.github.cuukenn.demo.encrypt.lectotype.gateway.rewrite.EncryptorResponseGatewayFilterFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.MessageBodyDecoder;
import org.springframework.cloud.gateway.filter.factory.rewrite.MessageBodyEncoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.codec.HttpMessageReader;

import java.util.List;
import java.util.Set;

/**
 * @author changgg
 */
@EnableConfigurationProperties(EncryptorConfig.class)
@ConditionalOnProperty(prefix = EncryptorConfig.PREFIX, name = "enable", havingValue = "true", matchIfMissing = true)
@Configuration(proxyBeanMethods = false)
public class EncryptorReactiveAutoConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorReactiveAutoConfiguration.class);

    @ConditionalOnBean(RedisTemplate.class)
    @ConditionalOnMissingBean(name = "defaultNonceChecker")
    @Bean("defaultNonceChecker")
    public InRedisNonceChecker redisNonceChecker(RedisTemplate<Object, Object> redisTemplate, EncryptorConfig config) {
        logger.info("register in redis nonce checker");
        return new InRedisNonceChecker(redisTemplate, config.getNonceCheckerConfig().getOffsetTime());
    }

    @ConditionalOnMissingBean(name = "defaultNonceChecker")
    @Bean("defaultNonceChecker")
    public InMemoryNonceChecker memoryNonceChecker(EncryptorConfig config) {
        logger.info("register in memory nonce checker");
        return new InMemoryNonceChecker(config.getNonceCheckerConfig().getInMemoryCacheSize(), config.getNonceCheckerConfig().getOffsetTime());
    }

    @ConditionalOnClass(GatewayFilterFactory.class)
    @ConditionalOnBean(value = {EncryptorEncoder.class, SignerEncoder.class})
    @Bean
    public EncryptorRequestGatewayFilterFactory encryptorRequestGatewayFilterFactory(EncryptorEncoder encryptorEncoder, SignerEncoder signerEncoder, List<CheckerStrategy> checkerStrategies) {
        logger.info("register request encryptor");
        return new EncryptorRequestGatewayFilterFactory(encryptorEncoder, signerEncoder, checkerStrategies);
    }

    @ConditionalOnClass(GatewayFilterFactory.class)
    @ConditionalOnBean(value = {EncryptorEncoder.class, SignerEncoder.class})
    @Bean
    public EncryptorResponseGatewayFilterFactory encryptorResponseGatewayFilterFactory(List<HttpMessageReader<?>> messageReaders, Set<MessageBodyDecoder> messageBodyDecoders, Set<MessageBodyEncoder> messageBodyEncoders, EncryptorEncoder encryptorEncoder, SignerEncoder signerEncoder) {
        logger.info("register response encryptor");
        return new EncryptorResponseGatewayFilterFactory(messageReaders, messageBodyDecoders, messageBodyEncoders, encryptorEncoder, signerEncoder);
    }
}
