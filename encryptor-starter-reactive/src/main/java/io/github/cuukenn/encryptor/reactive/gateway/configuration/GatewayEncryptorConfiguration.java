package io.github.cuukenn.encryptor.reactive.gateway.configuration;

import io.github.cuukenn.encryptor.config.CryptoConfig;
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
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyRequestBodyGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyResponseBodyGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
    @ConditionalOnMissingBean(EncryptorRequestParameterFilter.class)
    @Bean
    public EncryptorRequestParameterFilter encryptorRequestParameterGatewayFilterFactory() {
        logger.info("register request parameter encryptor");
        return new EncryptorRequestParameterFilter();
    }

    @ConditionalOnClass(GlobalFilter.class)
    @Bean
    @ConditionalOnMissingBean(EncryptorRequestFilter.class)
    public EncryptorRequestFilter encryptorRequestGatewayFilterFactory(ModifyRequestBodyGatewayFilterFactory gatewayFilterFactory) {
        logger.info("register request body encryptor");
        return new EncryptorRequestFilter(gatewayFilterFactory);
    }

    @ConditionalOnClass(GlobalFilter.class)
    @ConditionalOnMissingBean(EncryptorResponseFilter.class)
    @Bean
    public EncryptorResponseFilter encryptorResponseGatewayFilterFactory(ModifyResponseBodyGatewayFilterFactory gatewayFilterFactory) {
        logger.info("register response encryptor");
        return new EncryptorResponseFilter(gatewayFilterFactory);
    }

    @ConditionalOnClass(GlobalFilter.class)
    @ConditionalOnMissingBean(EncryptorGatewayFilter.class)
    @Bean
    public EncryptorGatewayFilter encryptorGatewayFilterFactory(EncryptorConfig encryptorConfig, GatewayEncryptorConfig config, Map<String, EncryptorFacadeFactory<CryptoConfig>> facadeFactories, Map<String, DataConverter> dataConverters) {
        logger.info("register gateway encryptor");
        return new EncryptorGatewayFilter(config,
                configL -> {
                    CryptoConfig cryptoConfig = CryptoConfig.getOrDefaultFill(encryptorConfig.getCryptoConfig(), configL);
                    return facadeFactories.get(cryptoConfig.getEncryptorFactory()).apply(cryptoConfig);
                },
                configM -> dataConverters.get(CryptoConfig.getOrDefaultFill(encryptorConfig.getCryptoConfig(), configM).getEncryptorConverter())
        );
    }
}
