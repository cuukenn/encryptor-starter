package io.github.cuukenn.encryptor.reactive.gateway.configuration;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.config.CryptoExecutorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayFilterConfig;
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
import org.springframework.cloud.gateway.filter.NettyWriteResponseFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;

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
     * 容量由 {@code encryptor.config.reactive.gateway.crypto-executor.*} 配置（默认 CPU 核数 + 1000）；
     * 指标模块从同一实例读队列深度；需要自己的线程/队列策略时覆盖本 bean。
     */
    @Bean(destroyMethod = "dispose")
    @ConditionalOnMissingBean
    public CryptoExecutor cryptoExecutor(GatewayEncryptorConfig config) {
        CryptoExecutorConfig exec = config.getCryptoExecutor();
        if (exec.getThreads() < 0) {
            throw new EncryptorException("encryptor.config.reactive.gateway.crypto-executor.threads 非法: "
                + exec.getThreads() + "（0 = CPU 核数，正数 = 指定线程数）");
        }
        if (exec.getQueueCapacity() <= 0) {
            throw new EncryptorException("encryptor.config.reactive.gateway.crypto-executor.queue-capacity 必须为正: "
                + exec.getQueueCapacity() + "（队列用于吸收突发，打满回 503）");
        }
        int threads = exec.getThreads() > 0 ? exec.getThreads() : Runtime.getRuntime().availableProcessors();
        logger.info("密码学执行器: threads={}, queue={}（threads<=0 表示 CPU 核数）", threads, exec.getQueueCapacity());
        return new CryptoExecutor(threads, exec.getQueueCapacity());
    }

    @Bean
    public EncryptorGatewayFilter encryptorGatewayFilter(GatewayEncryptorConfig config,
                                                         EncryptorConfig reactiveConfig,
                                                         DefaultProtocol protocol,
                                                         CryptoExecutor cryptoExecutor) {
        validateFailureStatus(reactiveConfig.getFailureStatus());
        validateFilterOrder(config.getFilterConfig());
        GatewayFilterConfig orders = config.getFilterConfig();
        logger.info("加密 GlobalFilter 链序: jwks={}, 请求={}, 响应={}（锚点: NettyWriteResponseFilter={}；"
                + "契约: jwks < 请求 < 业务过滤器，响应 < NettyWrite。下游要在明文视图内运行的自定义 GlobalFilter "
                + "order 必须大于请求过滤器；在 {} 之前读请求 body 的过滤器会让加密过滤器读到空流）",
            orders.getJwksFilterOrder(), orders.getEncryptorFilterOrder(), orders.getEncryptorResFilterOrder(),
            NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER, orders.getEncryptorFilterOrder());
        if (config.isSkipAble()) {
            logger.warn("encryptor.config.reactive.gateway.skip-able=true：带 {} 头的请求会完全绕过解密与加密，"
                    + "该头就是事实上的共享密钥，请确保只有可信来源能设置它（网关前的 TLS/代理必须剥离外部同名头）",
                GatewayConstant.SKIP_HEADER);
        }
        validateCryptoKids(config, protocol);
        return new EncryptorGatewayFilter(config, reactiveConfig, protocol, cryptoExecutor);
    }

    /**
     * GlobalFilter order 全部可配（下游要插入鉴权/限流/trace 等过滤器时必须调），但相对顺序错了
     * 不报错而是静默退化：响应过滤器跑到 NettyWrite 之后会让响应加密改写失效（明文直出）。
     * 链序契约必须在启动期校验。
     */
    static void validateFilterOrder(GatewayFilterConfig orders) {
        int writeOrder = NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER;
        boolean ok = orders.getJwksFilterOrder() < orders.getEncryptorFilterOrder()
            && orders.getEncryptorResFilterOrder() < writeOrder;
        if (!ok) {
            throw new EncryptorException("过滤器 order 违反链序契约: 要求 jwks(" + orders.getJwksFilterOrder()
                + ") < 请求过滤器(" + orders.getEncryptorFilterOrder()
                + ")，且响应过滤器(" + orders.getEncryptorResFilterOrder() + ") < NettyWriteResponseFilter("
                + writeOrder + ")。响应过滤器必须包在 NettyWrite 之内，否则响应加密会静默失效（明文直出）");
        }
    }

    @Bean
    public EncryptorResponseFilter encryptorResponseFilter(GatewayEncryptorConfig config,
                                                           EncryptorConfig reactiveConfig,
                                                           DefaultProtocol protocol,
                                                           CryptoExecutor cryptoExecutor) {
        return new EncryptorResponseFilter(config, reactiveConfig, protocol, cryptoExecutor);
    }

    /**
     * uri 级 kid 白名单必须在启动期与密钥库交叉校验：kid 拼错时该 uri 会恒定 400，且无任何告警。
     */
    static void validateCryptoKids(GatewayEncryptorConfig config, DefaultProtocol protocol) {
        if (config.getCryptoConfig() != null) {
            for (Map.Entry<String, List<String>> entry : config.getCryptoConfig().entrySet()) {
                if (entry.getValue() == null) {
                    continue;
                }
                for (String kid : entry.getValue()) {
                    if (!protocol.keys().contains(kid)) {
                        throw new EncryptorException("encryptor.config.reactive.gateway.crypto-config["
                            + entry.getKey() + "] 引用了不存在的 kid: " + kid);
                    }
                }
            }
        }
        if (config.getRoutes() != null) {
            for (Map.Entry<String, io.github.cuukenn.encryptor.config.base.RouteRule> entry
                : config.getRoutes().entrySet()) {
                List<String> kids = entry.getValue() == null ? null : entry.getValue().getKids();
                if (kids == null) {
                    continue;
                }
                for (String kid : kids) {
                    if (!protocol.keys().contains(kid)) {
                        throw new EncryptorException("encryptor.config.reactive.gateway.routes["
                            + entry.getKey() + "].kids 引用了不存在的 kid: " + kid);
                    }
                }
            }
        }
    }

    /**
     * 失败状态码必须能被 {@link HttpStatus#valueOf(int)} 映射：网关失败面用它设状态，
     * Spring 枚举里没有的码（如 499）会在每次失败时抛 IAE，把配置错误变成 500。
     */
    static void validateFailureStatus(int status) {
        if (HttpStatus.resolve(status) == null) {
            throw new EncryptorException("encryptor.config.reactive.failure-status 非法: " + status
                + "（必须是 Spring 已知的 HTTP 状态码）");
        }
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