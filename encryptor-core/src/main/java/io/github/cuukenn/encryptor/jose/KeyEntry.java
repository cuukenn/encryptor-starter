package io.github.cuukenn.encryptor.jose;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 一把已解析好的服务端密钥（{@link ServerKeyStore} 的内部存储单元，也是 {@link KeyEntryParser} 的产出）。
 *
 * <p>RSA / EC 这类 JCE 原生支持的密钥会填 {@link #privateKey()} / {@link #publicKey()}；
 * 需要第三方密码学库的类型（例如国密 SM2）可以把"库私有"的私钥句柄放在
 * {@link #nativePrivateKey()}，core 不关心它的具体类型，也不会因而引入任何编译期依赖。</p>
 *
 * @author changgg
 */
public final class KeyEntry {

    private final String kid;
    private final KeyType type;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final PublicKeyInfo publicKeyInfo;
    private final Object nativePrivateKey;

    /**
     * @param kid              密钥标识
     * @param type             密钥类型
     * @param privateKey       JCE 私钥（可为 {@code null}，例如 SM2 走轻量级 API）
     * @param publicKey        JCE 公钥（可为 {@code null}）
     * @param publicKeyInfo    对外发布的公钥描述（SPKI + JWK），不可为 {@code null}
     * @param nativePrivateKey 第三方库私钥句柄（不透明对象，可为 {@code null}）
     */
    public KeyEntry(String kid, KeyType type, PrivateKey privateKey, PublicKey publicKey,
                    PublicKeyInfo publicKeyInfo, Object nativePrivateKey) {
        if (kid == null || kid.isEmpty()) {
            throw new IllegalArgumentException("key kid 不能为空");
        }
        if (type == null) {
            throw new IllegalArgumentException("key type 不能为空");
        }
        if (publicKeyInfo == null) {
            throw new IllegalArgumentException("key publicKeyInfo 不能为空");
        }
        this.kid = kid;
        this.type = type;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.publicKeyInfo = publicKeyInfo;
        this.nativePrivateKey = nativePrivateKey;
    }

    public String kid() {
        return kid;
    }

    public KeyType type() {
        return type;
    }

    /** JCE 私钥；SM2 等非 JCE 条目为 {@code null}。 */
    public PrivateKey privateKey() {
        return privateKey;
    }

    /** JCE 公钥；SM2 等非 JCE 条目为 {@code null}。 */
    public PublicKey publicKey() {
        return publicKey;
    }

    /** 公钥的 SPKI/JWK 描述（JWKS 发现端点用）。 */
    public PublicKeyInfo publicKeyInfo() {
        return publicKeyInfo;
    }

    /** 第三方库的私钥句柄（不透明对象）；无则为 {@code null}。 */
    public Object nativePrivateKey() {
        return nativePrivateKey;
    }

    /** 返回仅替换公钥描述的新条目（密钥库构建时用于标记 active）。 */
    public KeyEntry withPublicKeyInfo(PublicKeyInfo info) {
        return new KeyEntry(kid, type, privateKey, publicKey, info, nativePrivateKey);
    }
}
