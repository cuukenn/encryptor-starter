package io.github.cuukenn.encryptor.web.config;

import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.config.EncryptorConfig;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @author changgg
 */
@ConfigurationProperties(prefix = EncryptorConfig.PREFIX + ".web")
public class WebEncryptorConfig {
    /**
     * 过滤器配置
     */
    @NestedConfigurationProperty
    private WebFilterConfig filterConfig = new WebFilterConfig();
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

    public List<String> getBlackRequestContentType() {
        return blackReqContentType;
    }

    public void setBlackRequestContentType(List<String> blackRequestContentType) {
        this.blackReqContentType = blackRequestContentType;
    }

    public List<String> getBlackResponseContentType() {
        return blackResContentType;
    }

    public void setBlackResponseContentType(List<String> blackResponseContentType) {
        this.blackResContentType = blackResponseContentType;
    }

    public List<String> getBlackMethods() {
        return blackMethods;
    }

    public void setBlackMethods(List<String> blackMethods) {
        this.blackMethods = blackMethods;
    }

    public Map<String, CryptoConfig> getCryptoConfig() {
        return cryptoConfig;
    }

    public void setCryptoConfig(Map<String, CryptoConfig> cryptoConfig) {
        this.cryptoConfig = cryptoConfig;
    }
}
