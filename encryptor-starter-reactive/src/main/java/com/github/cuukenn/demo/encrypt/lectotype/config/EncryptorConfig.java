package com.github.cuukenn.demo.encrypt.lectotype.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * @author changgg
 */
@ConfigurationProperties(prefix = EncryptorConfig.PREFIX)
public class EncryptorConfig {
    public static final String PREFIX = "encryptor.config";
    @NestedConfigurationProperty
    private NonceCheckerConfig nonceCheckerConfig;

    public NonceCheckerConfig getNonceCheckerConfig() {
        return nonceCheckerConfig;
    }

    public void setNonceCheckerConfig(NonceCheckerConfig nonceCheckerConfig) {
        this.nonceCheckerConfig = nonceCheckerConfig;
    }
}
