package io.github.cuukenn.encryptor.jose;

/**
 * 服务端密钥类型（对应配置里的 {@code type}）。
 *
 * <p>决定用哪套 {@link CipherSuite} 解封 CEK：RSA-OAEP-256 要 RSA 密钥，SM2 要国密密钥。
 * 密钥类型与 {@code alg} 不匹配时，套件必须在解封前直接拒绝，而不是等底层解密报错。
 *
 * @author changgg
 */
public enum KeyType {

    /** RSA（{@code RSA-OAEP-256}），JCE 可用，无需额外 Provider。 */
    RSA,

    /** 国密 SM2（{@code SM2}，C1C3C2），走 BouncyCastle 轻量级 API，不注册全局 Provider。 */
    SM2,

    /**
     * NIST P-256（{@code secp256r1}），用于 {@code ECDH-ES} 直接密钥协商。
     *
     * <p>私钥 PKCS#8、公钥 SPKI（Base64），JCE/SunEC 原生支持，无需额外 Provider。
     * 曲线名在 JWKS 里是 {@code crv=P-256}（注意与 {@link #SM2} 同为 {@code kty=EC}，靠 {@code crv} 区分）。</p>
     */
    EC
}
