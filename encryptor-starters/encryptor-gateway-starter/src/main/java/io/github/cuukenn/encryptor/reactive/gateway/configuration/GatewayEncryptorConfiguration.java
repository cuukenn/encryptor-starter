package io.github.cuukenn.encryptor.reactive.gateway.configuration;

import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import io.github.cuukenn.encryptor.reactive.gateway.discovery.JwksEndpointFilter;
import io.github.cuukenn.encryptor.reactive.gateway.filter.EncryptorGatewayFilter;
import io.github.cuukenn.encryptor.reactive.gateway.filter.EncryptorResponseFilter;
import io.github.cuukenn.encryptor.reactive.gateway.runtime.CryptoExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
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

    private static final Logger logger = LoggerFactory.getLogger(GatewayEncryptorConfiguration.class);

    /**
     * 密码学有界执行器：请求解密与响应加密共用同一个（队列满 → 503）。
     * 指标模块从同一实例读队列深度；需要自己的线程/队列策略时覆盖本 bean。
     */
    @Bean
    @ConditionalOnMissingBean
    public CryptoExecutor cryptoExecutor() {
        return CryptoExecutor.create();
    }

    @Bean
    public EncryptorGatewayFilter encryptorGatewayFilter(GatewayEncryptorConfig config,
                                                         EncryptorConfig reactiveConfig,
                                                         DefaultProtocol protocol,
                                                         CryptoExecutor cryptoExecutor) {
        if (config.isSkipAble()) {
            logger.warn("encryptor.config.reactive.gateway.skip-able=true：带 {} 头的请求会完全绕过解密与加密，"
                    + "该头就是事实上的共享密钥，请确保只有可信来源能设置它（网关前的 TLS/代理必须剥离外部同名头）",
                GatewayConstant.SKIP_HEADER);
        }
        return new EncryptorGatewayFilter(config, reactiveConfig, protocol, cryptoExecutor);
    }

    @Bean
    public EncryptorResponseFilter encryptorResponseFilter(GatewayEncryptorConfig config,
                                                           EncryptorConfig reactiveConfig,
                                                           DefaultProtocol protocol,
                                                           CryptoExecutor cryptoExecutor) {
        return new EncryptorResponseFilter(config, reactiveConfig, protocol, cryptoExecutor);
    }

    /**
     * JWKS 只读发现端点（网关自己响应、不转发下游）；order 取 filterConfig.jwksFilterOrder。
     *
     * <p>是 {@link JwksEndpointFilter WebFilter}（先于路由执行），不是 GlobalFilter —— 发现路径没有路由。</p>
     */
    @Bean
    public JwksEndpointFilter gatewayJwksEndpointFilter(GatewayEncryptorConfig config,
                                                        EncryptorConfig reactiveConfig,
                                                        DefaultProtocol protocol) {
        return new JwksEndpointFilter(protocol.keys(), reactiveConfig.getDiscovery(),
            config.getFilterConfig().getJwksFilterOrder());
    }
}