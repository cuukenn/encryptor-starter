package io.github.cuukenn.encryptor.reactive.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * @author changgg
 */
@ConfigurationProperties(prefix = EncryptorConfig.PREFIX)
public class EncryptorConfig {
    public static final String PREFIX = "encryptor.config.reactive";
    /**
     * 加密配置
     */
    @NestedConfigurationProperty
    private CryptoConfig cryptoConfig = new CryptoConfig();

    public CryptoConfig getCryptoConfig() {
        return cryptoConfig;
    }

    public void setCryptoConfig(CryptoConfig cryptoConfig) {
        this.cryptoConfig = cryptoConfig;
    }

}
