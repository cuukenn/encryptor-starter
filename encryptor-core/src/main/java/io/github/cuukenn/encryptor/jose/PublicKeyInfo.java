package io.github.cuukenn.encryptor.jose;

import java.util.Collections;
import java.util.Map;

/**
 * 对外发布的公钥描述（只含公钥，用于 JWKS 发现端点）。
 *
 * @author changgg
 */
public final class PublicKeyInfo {
    private final String kid;
    private final String alg;
    private final String spkiBase64;
    private final Map<String, Object> jwk;
    private final boolean active;

    /**
     * @param kid         密钥标识
     * @param alg         对外声明的算法名（{@code RSA-OAEP-256} / {@code ECDH-ES} / {@code SM2} 等）
     * @param spkiBase64  X.509 SubjectPublicKeyInfo 的 base64（不含 PEM 头尾）
     * @param jwk         只含公钥的标准 JWK
     * @param active      是否为当前推荐的 kid
     */
    public PublicKeyInfo(String kid, String alg, String spkiBase64, Map<String, Object> jwk, boolean active) {
        this.kid = kid;
        this.alg = alg;
        this.spkiBase64 = spkiBase64;
        this.jwk = Collections.unmodifiableMap(jwk);
        this.active = active;
    }

    public String kid() {
        return kid;
    }

    public String alg() {
        return alg;
    }

    /** X.509 SubjectPublicKeyInfo 的 base64（不含 PEM 头尾）。 */
    public String spkiBase64() {
        return spkiBase64;
    }

    /** 标准 JWK（kty/n/e/kid/alg/use），可直接被 WebCrypto importKey('jwk', ...) 使用。 */
    public Map<String, Object> jwk() {
        return jwk;
    }

    /** 是否为当前推荐的 kid。 */
    public boolean active() {
        return active;
    }
}
