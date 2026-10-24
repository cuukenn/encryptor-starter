package io.github.cuukenn.encryptor.web.config;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.config.base.RouteRule;
import io.github.cuukenn.encryptor.config.base.SkipListsConfigBase;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.kit.StrKit;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * web 侧（servlet）配置。报文大小上限与失败状态码已上移到全局 {@link EncryptorConfig}；
 * skip-* / black-* 名单字段与 alias 合并、预编译、告警机制继承 core 的
 * {@link SkipListsConfigBase}（skip 口径单点维护）。
 *
 * @author changgg
 */
@ConfigurationProperties(prefix = WebEncryptorConfig.PREFIX)
public class WebEncryptorConfig extends SkipListsConfigBase implements InitializingBean {
    public static final String PREFIX = EncryptorConfig.PREFIX + ".web";
    /**
     * 是否启用 web 侧过滤链。
     */
    private boolean enable = true;
    /**
     * 过滤器顺序配置。
     */
    @NestedConfigurationProperty
    private WebFilterConfig filterConfig = new WebFilterConfig();
    /**
     * uri 级 kid 白名单：uri 正则 → 该 uri 只接受的 kid 列表；空列表 = 不限。
     * 含 {@code .} 的正则 key 必须用括号写法：{@code crypto-config["[^/pay/.*]"]: [k1, k2]}。
     */
    private Map<String, List<String>> cryptoConfig = new LinkedHashMap<>();
    /**
     * per-route 策略（新键，与 crypto-config 并存）：uri 正则 → {@link RouteRule}。
     * 当前实现 kids（与 crypto-config 同正则命中取并集）；键结构已固定，后续 enc/ttl 等
     * 字段往 RouteRule 里加都是增量绑定。正则 key 含 {@code .} 时同样必须用 {@code [key]} 括号写法。
     */
    private Map<String, RouteRule> routes = new LinkedHashMap<>();

    public boolean isEnable() {
        return enable;
    }

    public void setEnable(boolean enable) {
        this.enable = enable;
    }

    public WebFilterConfig getFilterConfig() {
        return filterConfig;
    }

    public void setFilterConfig(WebFilterConfig filterConfig) {
        this.filterConfig = filterConfig;
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
        validateFilterOrder();
        Map<String, List<String>> crypto = getCryptoConfig();
        if (crypto != null) {
            StrKit.precompile(PREFIX + ".crypto-config", crypto.keySet());
        }
        if (routes != null) {
            StrKit.precompile(PREFIX + ".routes", routes.keySet());
        }
    }

    /**
     * 链序是载荷契约：门面必须包住参数/请求体视图，响应过滤器必须在门面内层（否则读不到 CEK，
     * 响应会静默变明文）。覆盖默认值后必须在这里 fail-fast，不能等线上发现。
     */
    private void validateFilterOrder() {
        WebFilterConfig filter = getFilterConfig();
        if (filter == null) {
            throw new EncryptorException("encryptor.config.web.filter-config 不能为空");
        }
        int jwks = filter.getJwksFilterOrder();
        int facade = filter.getEncryptorFilterOrder();
        int params = filter.getEncryptorReqParamsFilterOrder();
        int body = filter.getEncryptorReqBodyFilterOrder();
        int response = filter.getEncryptorResFilterOrder();
        if (!(jwks < facade && facade < params && params < body && body < response)) {
            throw new EncryptorException("encryptor.config.web.filter-config 顺序非法: "
                + "要求 jwks < facade < params < body < res，实际 jwks=" + jwks + ", facade=" + facade
                + ", params=" + params + ", body=" + body + ", res=" + response);
        }
    }
}
