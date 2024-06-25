package io.github.cuukenn.encryptor.pojo;

/**
 * @author changgg
 */
public class EncryptorDataWrapper {
    private final String nonce;
    private final Long timestamp;
    private final String signature;
    private final String key;
    private final String data;

    public EncryptorDataWrapper(String nonce, Long timestamp, String signature, String key, String data) {
        this.nonce = nonce;
        this.timestamp = timestamp;
        this.signature = signature;
        this.key = key;
        this.data = data;
    }

    public String getData() {
        return data;
    }

    public String getNonce() {
        return nonce;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public String getSignature() {
        return signature;
    }

    public String getKey() {
        return key;
    }
}
