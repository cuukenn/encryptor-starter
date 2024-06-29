package io.github.cuukenn.encryptor.reactive.config;

import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.reactive.constant.EncryptorConstant;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * @author changgg
 */
@ConfigurationProperties(prefix = EncryptorConfig.PREFIX)
public class EncryptorConfig {
    public static final String PREFIX = "encryptor.config.reactive";
    @NestedConfigurationProperty
    private NonceCheckerConfig nonceCheckerConfig = new NonceCheckerConfig();
    @NestedConfigurationProperty
    private CryptoConfig cryptoConfig = new CryptoConfig("RSA", EncryptorConstant.DEFAULT_ENCRYPTOR_FACTORY, EncryptorConstant.ALL_IN_BODY_CONVERTER);

    public CryptoConfig getCryptoConfig() {
        return cryptoConfig;
    }

    public void setCryptoConfig(CryptoConfig cryptoConfig) {
        this.cryptoConfig = cryptoConfig;
    }

    public NonceCheckerConfig getNonceCheckerConfig() {
        return nonceCheckerConfig;
    }

    public void setNonceCheckerConfig(NonceCheckerConfig nonceCheckerConfig) {
        this.nonceCheckerConfig = nonceCheckerConfig;
    }
}
