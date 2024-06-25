package io.github.cuukenn.encryptor.config;

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
    @NestedConfigurationProperty
    private ASymmetricCryptoConfig ascConfig;

    public NonceCheckerConfig getNonceCheckerConfig() {
        return nonceCheckerConfig;
    }

    public void setNonceCheckerConfig(NonceCheckerConfig nonceCheckerConfig) {
        this.nonceCheckerConfig = nonceCheckerConfig;
    }

    public ASymmetricCryptoConfig getAscConfig() {
        return ascConfig;
    }

    public void setAscConfig(ASymmetricCryptoConfig ascConfig) {
        this.ascConfig = ascConfig;
    }
}
