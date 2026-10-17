package io.github.cuukenn.encryptor.reactive.gateway.configuration;

import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.filter.EncryptorGatewayFilter;
import io.github.cuukenn.encryptor.reactive.gateway.filter.EncryptorResponseFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 网关 v2 自动装配：两个 {@link GlobalFilter}（请求决策+一次解密 / 响应加密回写），
 * 共用 reactive 侧装配的同一份 {@link DefaultProtocol}。
 *
 * @author changgg
 */
@ConditionalOnClass(GlobalFilter.class)
@ConditionalOnProperty(prefix = GatewayEncryptorConfig.PREFIX, name = "enable", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(GatewayEncryptorConfig.class)
@Configuration(proxyBeanMethods = false)
public class GatewayEncryptorConfiguration {

    @Bean
    public EncryptorGatewayFilter encryptorGatewayFilter(GatewayEncryptorConfig config,
                                                         EncryptorConfig reactiveConfig,
                                                         DefaultProtocol protocol) {
        return new EncryptorGatewayFilter(config, reactiveConfig, protocol);
    }

    @Bean
    public EncryptorResponseFilter encryptorResponseFilter(GatewayEncryptorConfig config,
                                                           EncryptorConfig reactiveConfig,
                                                           DefaultProtocol protocol) {
        return new EncryptorResponseFilter(config, reactiveConfig, protocol);
    }
}
