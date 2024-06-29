package io.github.cuukenn.encryptor.pojo;

/**
 * @author changgg
 */
public class EncryptorDataWrapper {
    private String nonce;
    private Long timestamp;
    private String signature;
    private String key;
    private String data;

    public EncryptorDataWrapper() {
    }

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

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public void setData(String data) {
        this.data = data;
    }
}
