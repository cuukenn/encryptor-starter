package io.github.cuukenn.encryptor.config.base;

import io.github.cuukenn.encryptor.jose.KeyType;

/**
 * 一把服务端密钥的纯配置模型（无 Spring 依赖，servlet/reactive 两侧共用）。
 *
 * @author changgg
 */
public class KeyMaterialConfigBase {
    /**
     * 密钥标识（kid），客户端在 JWE 头里选用；轮换时多钥并存。
     */
    private String kid;
    /**
     * 密钥类型：RSA（默认）、EC 或 SM2。
     */
    private KeyType type = KeyType.RSA;
    /**
     * Base64 编码的 PKCS#8 私钥（SM2 亦为 PKCS#8）。
     */
    private String privateKey;
    /**
     * Base64 编码的公钥：RSA/EC 为 X.509/SPKI；SM2 为 SPKI 或裸 64 字节 x||y。
     */
    private String publicKey;

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public KeyType getType() {
        return type;
    }

    public void setType(KeyType type) {
        this.type = type;
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
