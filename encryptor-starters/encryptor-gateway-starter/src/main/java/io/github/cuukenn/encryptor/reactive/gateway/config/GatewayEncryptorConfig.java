package io.github.cuukenn.encryptor.reactive.gateway.config;

import io.github.cuukenn.encryptor.config.base.RouteRule;
import io.github.cuukenn.encryptor.config.base.SkipListsConfigBase;
import io.github.cuukenn.encryptor.kit.StrKit;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 网关侧 v2 配置（前缀 {@code encryptor.config.reactive.gateway}）。
 *
 * <p>failureStatus / maxRequestSize / maxResponseSize / require-encrypted / bypass / discovery
 * 统一读 {@code reactive.config.EncryptorConfig}（reactive 前缀），此处不再重复声明（双写警告）；
 * skip-* / black-* 名单字段与 alias 合并、预编译、告警机制继承 core 的
 * {@link SkipListsConfigBase}（skip 口径单点维护）。</p>
 *
 * @author changgg
 */
@ConfigurationProperties(prefix = GatewayEncryptorConfig.PREFIX)
public class GatewayEncryptorConfig extends SkipListsConfigBase implements InitializingBean {
    public static final String PREFIX = "encryptor.config.reactive.gateway";

    /**
     * skip 开关：为 true 时带 {@code x-skip-encryptor} 头的请求全程透传；
     * 只允许内网/共享密钥部署，启动时会告警。
     */
    private boolean skipAble;
    /**
     * 两个过滤器的 order（v1 的 skip/params/body 三 order 已随架构合并删除）。
     */
    @NestedConfigurationProperty
    private GatewayFilterConfig filterConfig = new GatewayFilterConfig();
    /**
     * 密码学有界执行器容量（线程/队列）；默认线程数 = CPU 核数、队列 1000。
     */
    @NestedConfigurationProperty
    private CryptoExecutorConfig cryptoExecutor = new CryptoExecutorConfig();
    /**
     * uri 级 kid 白名单：正则 → 该 uri 允许的 kid 集合；空 = 全部允许。
     * 正则 key 含 {@code .} 时必须用 {@code [key]} 括号写法，否则 Spring 会静默改坏 key。
     */
    private Map<String, List<String>> cryptoConfig = new LinkedHashMap<>();
    /**
     * per-route 策略（新键，与 crypto-config 并存）：uri 正则 → {@link RouteRule}。
     * 当前实现 kids（与 crypto-config 同正则命中取并集）；键结构已固定，后续 enc/ttl 等
     * 字段往 RouteRule 里加都是增量绑定。正则 key 含 {@code .} 时同样必须用 {@code [key]} 括号写法。
     */
    private Map<String, RouteRule> routes = new LinkedHashMap<>();

    public boolean isSkipAble() {
        return skipAble;
    }

    public void setSkipAble(boolean skipAble) {
        this.skipAble = skipAble;
    }

    public GatewayFilterConfig getFilterConfig() {
        return filterConfig;
    }

    public void setFilterConfig(GatewayFilterConfig filterConfig) {
        this.filterConfig = filterConfig;
    }

    public CryptoExecutorConfig getCryptoExecutor() {
        return cryptoExecutor;
    }

    public void setCryptoExecutor(CryptoExecutorConfig cryptoExecutor) {
        this.cryptoExecutor = cryptoExecutor;
    }

    public Map<String, List<String>> getCryptoConfig() {
        return cryptoConfig;
    }

    public void setCryptoConfig(Map<String, List<String>> cryptoConfig) {
        this.cryptoConfig = cryptoConfig;
    }

    public Map<String, RouteRule> getRoutes() {
        return routes;
    }

    public void setRoutes(Map<String, RouteRule> routes) {
        this.routes = routes;
    }

    @Override
    public void afterPropertiesSet() {
        initSkipLists(PREFIX);
        Map<String, List<String>> crypto = getCryptoConfig();
        if (crypto != null) {
            StrKit.precompile(PREFIX + ".crypto-config", crypto.keySet());
        }
        if (routes != null) {
            StrKit.precompile(PREFIX + ".routes", routes.keySet());
        }
    }
}
