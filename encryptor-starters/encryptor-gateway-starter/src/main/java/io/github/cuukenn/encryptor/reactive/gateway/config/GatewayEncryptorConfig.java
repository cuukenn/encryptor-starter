package io.github.cuukenn.encryptor.reactive.gateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 网关侧 v2 配置（前缀 {@code encryptor.config.reactive.gateway}）。
 *
 * <p>failureStatus / maxRequestSize / maxResponseSize / require-encrypted / bypass / discovery
 * 统一读 {@code reactive.config.EncryptorConfig}（reactive 前缀），此处不再重复声明（双写警告）。</p>
 *
 * <p>跳过名单的新名字是 {@code skip-*}；旧名 {@code black-*} 仍可绑定（alias，已弃用），
 * 由 {@link #afterPropertiesSet()} 在绑定完成后并入生效名单。</p>
 *
 * @author changgg
 */
@ConfigurationProperties(prefix = GatewayEncryptorConfig.PREFIX)
public class GatewayEncryptorConfig implements InitializingBean {
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
     * 跳过加密的 uri 名单（正则整串匹配）。
     *
     * <p>旧名 {@code black-uris} 仍可绑定（已弃用）：那个名字与语义相反——命中即<b>跳过</b>，不是拦截。</p>
     */
    private final List<String> skipUris = new ArrayList<>();
    /**
     * 跳过加密的方法名单。旧名 {@code black-methods} 仍可绑定（已弃用）。
     */
    private final List<String> skipMethods = new ArrayList<>();
    /**
     * 请求方向：命中该 content-type 名单则请求不解密（响应也不加密）。旧名 {@code black-req-content-type} 仍可绑定（已弃用）。
     */
    private final List<String> skipReqContentType = new ArrayList<>();
    /**
     * 响应方向：命中该 content-type 名单则响应不包装（组装响应时判断）。旧名 {@code black-res-content-type} 仍可绑定（已弃用）。
     */
    private final List<String> skipResContentType = new ArrayList<>();
    /**
     * 旧名 {@code black-*} 的绑定目标（已弃用）：绑定完成后由 {@link #afterPropertiesSet()} 并入上面的 skip 名单。
     * 之所以单独留一份，是因为 Spring Boot 对集合属性是「就地绑定（clear + 回填）」，
     * 若新旧名字共用同一个 list，后绑定的那个会把先绑定的清掉。
     */
    private final List<String> blackUris = new ArrayList<>();
    private final List<String> blackMethods = new ArrayList<>();
    private final List<String> blackReqContentType = new ArrayList<>();
    private final List<String> blackResContentType = new ArrayList<>();
    /**
     * 旧名 alias 的弃用告警。
     */
    private static final Logger LOG = LoggerFactory.getLogger(GatewayEncryptorConfig.class);
    /**
     * uri 级 kid 白名单：正则 → 该 uri 允许的 kid 集合；空 = 全部允许。
     * 正则 key 含 {@code .} 时必须用 {@code [key]} 括号写法，否则 Spring 会静默改坏 key。
     */
    private Map<String, List<String>> cryptoConfig = new LinkedHashMap<>();

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

    public List<String> getSkipUris() {
        return skipUris;
    }

    public void setSkipUris(List<String> skipUris) {
        replace(this.skipUris, skipUris);
    }

    public List<String> getSkipMethods() {
        return skipMethods;
    }

    public void setSkipMethods(List<String> skipMethods) {
        replace(this.skipMethods, skipMethods);
    }

    /**
     * @deprecated 旧名 alias（名字与语义相反：命中即跳过）；请改用 {@link #setSkipUris(List)}。
     */
    @Deprecated
    public List<String> getBlackUris() {
        return blackUris;
    }

    /** @deprecated 见 {@link #getBlackUris()}。 */
    @Deprecated
    public void setBlackUris(List<String> blackUris) {
        replace(this.blackUris, blackUris);
    }

    /** @deprecated 旧名 alias；请改用 {@link #setSkipMethods(List)}。 */
    @Deprecated
    public List<String> getBlackMethods() {
        return blackMethods;
    }

    /** @deprecated 见 {@link #getBlackMethods()}。 */
    @Deprecated
    public void setBlackMethods(List<String> blackMethods) {
        replace(this.blackMethods, blackMethods);
    }

    public List<String> getSkipReqContentType() {
        return skipReqContentType;
    }

    public void setSkipReqContentType(List<String> skipReqContentType) {
        replace(this.skipReqContentType, skipReqContentType);
    }

    public List<String> getSkipResContentType() {
        return skipResContentType;
    }

    public void setSkipResContentType(List<String> skipResContentType) {
        replace(this.skipResContentType, skipResContentType);
    }

    /** @deprecated 旧名 alias；请改用 {@link #setSkipReqContentType(List)}。 */
    @Deprecated
    public List<String> getBlackReqContentType() {
        return blackReqContentType;
    }

    /** @deprecated 见 {@link #getBlackReqContentType()}。 */
    @Deprecated
    public void setBlackReqContentType(List<String> blackReqContentType) {
        replace(this.blackReqContentType, blackReqContentType);
    }

    /** @deprecated 旧名 alias；请改用 {@link #setSkipResContentType(List)}。 */
    @Deprecated
    public List<String> getBlackResContentType() {
        return blackResContentType;
    }

    /** @deprecated 见 {@link #getBlackResContentType()}。 */
    @Deprecated
    public void setBlackResContentType(List<String> blackResContentType) {
        replace(this.blackResContentType, blackResContentType);
    }

    @Override
    public void afterPropertiesSet() {
        mergeAlias("black-uris", skipUris, blackUris);
        mergeAlias("black-methods", skipMethods, blackMethods);
        mergeAlias("black-req-content-type", skipReqContentType, blackReqContentType);
        mergeAlias("black-res-content-type", skipResContentType, blackResContentType);
    }

    /** 旧名并入生效名单（去重、幂等），并按需落一次弃用 WARN（P3-4 的迁移提示）。 */
    private void mergeAlias(String oldName, List<String> target, List<String> alias) {
        if (alias == null || alias.isEmpty()) {
            return;
        }
        LOG.warn("配置 {}.{} 已弃用（名字与语义相反：命中即跳过），请改用 {}.{}；本次仍生效",
            PREFIX, oldName, PREFIX, oldName.replace("black-", "skip-"));
        for (String value : alias) {
            if (value != null && !target.contains(value)) {
                target.add(value);
            }
        }
    }

    /** 覆盖式写入（与 Spring Boot 对集合属性的就地绑定语义保持一致）。 */
    private static void replace(List<String> target, List<String> values) {
        target.clear();
        if (values != null) {
            target.addAll(values);
        }
    }

    public Map<String, List<String>> getCryptoConfig() {
        return cryptoConfig;
    }

    public void setCryptoConfig(Map<String, List<String>> cryptoConfig) {
        this.cryptoConfig = cryptoConfig;
    }
}
