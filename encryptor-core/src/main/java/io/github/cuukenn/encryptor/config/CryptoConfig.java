package io.github.cuukenn.encryptor.config;

/**
 * @author changgg
 */
public class CryptoConfig {
    private String privateKey;
    private String publicKey;
    private String algorithm;
    private String encryptorFactory;
    private String encryptorConverter;

    @SuppressWarnings("unused")
    public CryptoConfig() {
    }

    public CryptoConfig(String algorithm, String encryptorFactory) {
        this.algorithm = algorithm;
        this.encryptorFactory = encryptorFactory;
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
