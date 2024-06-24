package com.github.cuukenn.demo.encrypt.lectotype.pojo;

/**
 * @author changgg
 */
public class EncryptorDataWrapper {
    private final String nonce;
    private final Long timestamp;
    private final String signature;
    private final String data;

    public EncryptorDataWrapper(String nonce, Long timestamp, String signature, String data) {
        this.nonce = nonce;
        this.timestamp = timestamp;
        this.signature = signature;
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
}
