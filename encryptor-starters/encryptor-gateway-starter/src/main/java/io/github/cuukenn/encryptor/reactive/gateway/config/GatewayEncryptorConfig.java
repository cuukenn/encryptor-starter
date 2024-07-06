package io.github.cuukenn.encryptor.reactive.gateway.config;

import io.github.cuukenn.encryptor.reactive.config.CryptoConfig;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @author changgg
 */
@ConfigurationProperties(prefix = EncryptorConfig.PREFIX + ".gateway")
public class GatewayEncryptorConfig {
    /**
     * 是否开启加密逻辑
     */
    private boolean enable = true;
    /**
     * 是否允许在加密开启的情况下通过前端配置来跳过加密处理
     * 主要用于测试联调， 真是发版不应该信任客户端任何设置
     */
    private boolean skipAble;
    /**
     * 过滤器配置
     */
    @NestedConfigurationProperty
    private GatewayFilterConfig filterConfig = new GatewayFilterConfig();
    /**
     * 加密配置
     */
    private Map<String, CryptoConfig> cryptoConfig = new LinkedHashMap<>();
    /**
     * 白名单地址
     */
    private List<String> blackUris = new ArrayList<>();
    /**
     * 白名单请求类型
     */
    private List<String> blackReqContentType = new ArrayList<>();
    /**
     * 白名单响应类型
     */
    private List<String> blackResContentType = new ArrayList<>();
    /**
     * 白名单方法
     */
    private List<String> blackMethods = new ArrayList<>();

    public boolean isEnable() {
        return enable;
    }

    public void setEnable(boolean enable) {
        this.enable = enable;
    }

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

    public Map<String, CryptoConfig> getCryptoConfig() {
        return cryptoConfig;
    }

    public void setCryptoConfig(Map<String, CryptoConfig> cryptoConfig) {
        this.cryptoConfig = cryptoConfig;
    }

    public List<String> getBlackUris() {
        return blackUris;
    }

    public void setBlackUris(List<String> blackUris) {
        this.blackUris = blackUris;
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

    public List<String> getBlackMethods() {
        return blackMethods;
    }

    public void setBlackMethods(List<String> blackMethods) {
        this.blackMethods = blackMethods;
    }
}
