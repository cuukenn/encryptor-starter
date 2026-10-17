package io.github.cuukenn.encryptor.web.config;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * web 侧（servlet）配置。报文大小上限与失败状态码已上移到全局 {@link EncryptorConfig}。
 *
 * @author changgg
 */
@ConfigurationProperties(prefix = WebEncryptorConfig.PREFIX)
public class WebEncryptorConfig {
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
     */
    private List<String> blackUris = new ArrayList<>();
    /**
     * 完全跳过加解密的 HTTP 方法（整串正则）。
     */
    private List<String> blackMethods = new ArrayList<>();
    /**
     * 请求方向跳过的 Content-Type（整串正则，小写后匹配）。
     */
    private List<String> blackReqContentType = new ArrayList<>();
    /**
     * 响应方向跳过的 Content-Type（整串正则，链后 Content-Type 落定判定）。
     */
    private List<String> blackResContentType = new ArrayList<>();
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

    public List<String> getBlackUris() {
        return blackUris;
    }

    public void setBlackUris(List<String> blackUris) {
        this.blackUris = blackUris;
    }

    public List<String> getBlackMethods() {
        return blackMethods;
    }

    public void setBlackMethods(List<String> blackMethods) {
        this.blackMethods = blackMethods;
    }

    public List<String> getBlackReqContentType() {
        return blackReqContentType;
    }

    public void setBlackReqContentType(List<String> blackReqContentType) {
        this.blackReqContentType = blackReqContentType;
    }

    public List<String> getBlackResContentType() {
        return blackResContentType;
    }

    public void setBlackResContentType(List<String> blackResContentType) {
        this.blackResContentType = blackResContentType;
    }

    public Map<String, List<String>> getCryptoConfig() {
        return cryptoConfig;
    }

    public void setCryptoConfig(Map<String, List<String>> cryptoConfig) {
        this.cryptoConfig = cryptoConfig;
    }
}
