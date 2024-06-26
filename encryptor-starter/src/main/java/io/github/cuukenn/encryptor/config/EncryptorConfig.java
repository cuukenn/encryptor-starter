package io.github.cuukenn.encryptor.config;

import io.github.cuukenn.encryptor.constant.EncryptorConstant;
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
    private CryptoConfig cryptoConfig = new CryptoConfig("RSA", EncryptorConstant.DEFAULT_ENCRYPTOR_FACTORY);

    public NonceCheckerConfig getNonceCheckerConfig() {
        return nonceCheckerConfig;
    }

    public void setNonceCheckerConfig(NonceCheckerConfig nonceCheckerConfig) {
        this.nonceCheckerConfig = nonceCheckerConfig;
    }

    public CryptoConfig getCryptoConfig() {
        return cryptoConfig;
    }

    public void setCryptoConfig(CryptoConfig cryptoConfig) {
        this.cryptoConfig = cryptoConfig;
    }
}
