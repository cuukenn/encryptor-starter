package io.github.cuukenn.encryptor.reactive.config;

import io.github.cuukenn.encryptor.reactive.constant.EncryptorConstant;

import java.util.Optional;

/**
 * @author changgg
 */
public class CryptoConfig {
    /**
     * 私钥
     */
    private String privateKey;
    /**
     * 公钥
     */
    private String publicKey;
    /**
     * 密码套件
     */
    private String algorithm = "RSA";
    /**
     * 加密工厂
     */
    private String encryptorFactory = EncryptorConstant.DEFAULT_ENCRYPTOR_FACTORY;
    /**
     * 数据转化
     */
    private String encryptorConverter = EncryptorConstant.ALL_IN_ONE_CONVERTER;

    public CryptoConfig() {
    }

    private CryptoConfig(String privateKey, String publicKey, String algorithm, String encryptorFactory, String encryptorConverter) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.algorithm = algorithm;
        this.encryptorFactory = encryptorFactory;
        this.encryptorConverter = encryptorConverter;
    }

    public static CryptoConfig getOrDefaultFill(CryptoConfig defaultConfig, CryptoConfig cryptoConfig) {
        if (cryptoConfig == null) {
            return defaultConfig;
        }
        if (defaultConfig == null) {
            return cryptoConfig;
        }
        return new CryptoConfig(
                Optional.ofNullable(cryptoConfig.getPrivateKey()).orElseGet(defaultConfig::getPrivateKey),
                Optional.ofNullable(cryptoConfig.getPublicKey()).orElseGet(defaultConfig::getPublicKey),
                Optional.ofNullable(cryptoConfig.getAlgorithm()).orElseGet(defaultConfig::getAlgorithm),
                Optional.ofNullable(cryptoConfig.getEncryptorFactory()).orElseGet(defaultConfig::getEncryptorFactory),
                Optional.ofNullable(cryptoConfig.getEncryptorConverter()).orElseGet(defaultConfig::getEncryptorConverter)
        );
    }

    public String getEncryptorConverter() {
        return encryptorConverter;
    }

    public void setEncryptorConverter(String encryptorConverter) {
        this.encryptorConverter = encryptorConverter;
    }

    public String getEncryptorFactory() {
        return encryptorFactory;
    }

    public void setEncryptorFactory(String encryptorFactory) {
        this.encryptorFactory = encryptorFactory;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }


    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
