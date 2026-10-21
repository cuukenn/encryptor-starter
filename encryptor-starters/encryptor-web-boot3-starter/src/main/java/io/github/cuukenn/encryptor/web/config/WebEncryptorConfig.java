package io.github.cuukenn.encryptor.web.config;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.kit.StrKit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * web 侧（servlet）配置。报文大小上限与失败状态码已上移到全局 {@link EncryptorConfig}。
 *
 * <p>跳过名单的新名字是 {@code skip-*}；旧名 {@code black-*} 仍可绑定（alias，已弃用），
 * 由 {@link #afterPropertiesSet()} 在绑定完成后并入生效名单。</p>
 *
 * @author changgg
 */
@ConfigurationProperties(prefix = WebEncryptorConfig.PREFIX)
public class WebEncryptorConfig implements InitializingBean {
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
     * 完全跳过加解密的 uri（整串正则匹配，非通配符；前缀匹配请写 {@code .*}）。
     *
     * <p>旧名 {@code black-uris} 仍可绑定（已弃用）：那个名字与语义相反——命中即<b>跳过</b>，不是拦截。</p>
     */
    private final List<String> skipUris = new ArrayList<>();
    /**
     * 完全跳过加解密的 HTTP 方法（整串正则）。旧名 {@code black-methods} 仍可绑定（已弃用）。
     */
    private final List<String> skipMethods = new ArrayList<>();
    /**
     * 请求方向跳过的 Content-Type（整串正则，小写后匹配）。旧名 {@code black-req-content-type} 仍可绑定（已弃用）。
     */
    private final List<String> skipReqContentType = new ArrayList<>();
    /**
     * 响应方向跳过的 Content-Type（整串正则，链后 Content-Type 落定判定）。旧名 {@code black-res-content-type} 仍可绑定（已弃用）。
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
    private static final Logger LOG = LoggerFactory.getLogger(WebEncryptorConfig.class);
    /**
     * uri 级 kid 白名单：uri 正则 → 该 uri 只接受的 kid 列表；空列表 = 不限。
     * 含 {@code .} 的正则 key 必须用括号写法：{@code crypto-config["[^/pay/.*]"]: [k1, k2]}。
     */
    private Map<String, List<String>> cryptoConfig = new HashMap<>();

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
        // 名单正则全部在启动期编译：非法配置直接启动失败，不等第一个请求才 500
        StrKit.precompile(PREFIX + ".skip-uris", skipUris);
        StrKit.precompile(PREFIX + ".skip-methods", skipMethods);
        StrKit.precompile(PREFIX + ".skip-req-content-type", skipReqContentType);
        StrKit.precompile(PREFIX + ".skip-res-content-type", skipResContentType);
        Map<String, List<String>> crypto = getCryptoConfig();
        if (crypto != null) {
            StrKit.precompile(PREFIX + ".crypto-config", crypto.keySet());
        }
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
