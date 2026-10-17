package io.github.cuukenn.encryptor.reactive.gateway.config;

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
 * @author changgg
 */
@ConfigurationProperties(prefix = GatewayEncryptorConfig.PREFIX)
public class GatewayEncryptorConfig {
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
     */
    private List<String> blackUris = new ArrayList<>();
    /**
     * 跳过加密的方法名单。
     */
    private List<String> blackMethods = new ArrayList<>();
    /**
     * 请求方向：命中该 content-type 名单则请求不解密（响应也不加密）。
     */
    private List<String> blackReqContentType = new ArrayList<>();
    /**
     * 响应方向：命中该 content-type 名单则响应不包装（组装响应时判断）。
     */
    private List<String> blackResContentType = new ArrayList<>();
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
