package io.github.cuukenn.encryptor.web.config;

import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.config.EncryptorConfig;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @author changgg
 */
@ConfigurationProperties(prefix = EncryptorConfig.PREFIX + ".web")
public class WebEncryptorConfig {
    private Map<String, CryptoConfig> cryptoConfig = new LinkedHashMap<>();
    /**
     * 白名单地址
     */
    private List<String> blackUris = new ArrayList<>();
    /**
     * 白名单请求类型
     */
    private List<String> blackRequestContentType = new ArrayList<>();
    /**
     * 白名单响应类型
     */
    private List<String> blackResponseContentType = new ArrayList<>();
    /**
     * 白名单方法
     */
    private List<String> blackMethods = new ArrayList<>();

    public List<String> getBlackURIs() {
        return blackUris;
    }

    public void setBlackURIs(List<String> blackURIs) {
        this.blackUris = blackURIs;
    }

    public List<String> getBlackRequestContentType() {
        return blackRequestContentType;
    }

    public void setBlackRequestContentType(List<String> blackRequestContentType) {
        this.blackRequestContentType = blackRequestContentType;
    }

    public List<String> getBlackResponseContentType() {
        return blackResponseContentType;
    }

    public void setBlackResponseContentType(List<String> blackResponseContentType) {
        this.blackResponseContentType = blackResponseContentType;
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
