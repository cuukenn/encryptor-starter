package io.github.cuukenn.encryptor.reactive.gateway.configuration;

import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.facade.EncryptorFacadeFactory;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.configuration.EncryptorReactiveAutoConfiguration;
import io.github.cuukenn.encryptor.reactive.converter.DataConverter;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.rewrite.EncryptorGatewayFilter;
import io.github.cuukenn.encryptor.reactive.gateway.rewrite.EncryptorRequestFilter;
import io.github.cuukenn.encryptor.reactive.gateway.rewrite.EncryptorRequestParameterFilter;
import io.github.cuukenn.encryptor.reactive.gateway.rewrite.EncryptorResponseFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.NettyWriteResponseFilter;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyRequestBodyGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyResponseBodyGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

import java.util.Map;

/**
 * @author changgg
 */
@Configuration
@ConditionalOnProperty(prefix = EncryptorConfig.PREFIX + ".gateway", name = "enable", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(GatewayEncryptorConfig.class)
public class GatewayEncryptorConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorReactiveAutoConfiguration.class);

    @ConditionalOnClass(GlobalFilter.class)
    @ConditionalOnBean(value = {EncryptorEncoder.class, SignerEncoder.class})
    @ConditionalOnMissingBean(EncryptorRequestParameterFilter.class)
    @Bean
    @Order(EncryptorRequestParameterFilter.FILTER_ORDER)
    public EncryptorRequestParameterFilter encryptorRequestParameterGatewayFilterFactory() {
        logger.info("register request parameter encryptor");
        return new EncryptorRequestParameterFilter();
    }

    @ConditionalOnClass(GlobalFilter.class)
    @ConditionalOnBean(value = {EncryptorEncoder.class, SignerEncoder.class, ModifyRequestBodyGatewayFilterFactory.class})
    @Bean
    @ConditionalOnMissingBean(EncryptorRequestFilter.class)
    @Order(EncryptorRequestFilter.FILTER_ORDER)
    public EncryptorRequestFilter encryptorRequestGatewayFilterFactory(ModifyRequestBodyGatewayFilterFactory gatewayFilterFactory) {
        logger.info("register request body encryptor");
        return new EncryptorRequestFilter(gatewayFilterFactory);
    }

    @ConditionalOnClass(GlobalFilter.class)
    @ConditionalOnBean(value = {EncryptorEncoder.class, SignerEncoder.class, ModifyResponseBodyGatewayFilterFactory.class})
    @ConditionalOnMissingBean(EncryptorResponseFilter.class)
    @Bean
    @Order(NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1)
    public EncryptorResponseFilter encryptorResponseGatewayFilterFactory(ModifyResponseBodyGatewayFilterFactory gatewayFilterFactory) {
        logger.info("register response encryptor");
        return new EncryptorResponseFilter(gatewayFilterFactory);
    }

    @ConditionalOnClass(GlobalFilter.class)
    @ConditionalOnMissingBean(EncryptorGatewayFilter.class)
    @Bean
    @Order(NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1)
    public EncryptorGatewayFilter encryptorGatewayFilterFactory(EncryptorConfig encryptorConfig, GatewayEncryptorConfig config, Map<String, EncryptorFacadeFactory<CryptoConfig>> facadeFactories, Map<String, DataConverter> dataConverters) {
        logger.info("register gateway encryptor");
        return new EncryptorGatewayFilter(config,
                configL -> {
                    if (configL == null) {
                        configL = encryptorConfig.getCryptoConfig();
                    }
                    return facadeFactories.get(configL.getEncryptorFactory()).apply(configL);
                },
                configM -> {
                    if (configM == null) {
                        configM = encryptorConfig.getCryptoConfig();
                    }
                    return dataConverters.get(configM.getEncryptorConverter());
                });
    }
}
