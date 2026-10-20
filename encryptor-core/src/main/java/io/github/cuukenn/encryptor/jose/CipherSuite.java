package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.JWEHeader;

import java.util.Set;

/**
 * 算法套件 SPI：把"CEK 封装/解封"与"内容 AEAD"这两件事从 {@link JweCodec} 里抽出来，
 * 使 JWE 线格式（compact、单 {@code jwe} 字段）完全不随算法变化。
 *
 * <p>已实现：{@link JceCipherSuite}（RSA-OAEP-256 + AES-GCM）、国密套件（SM2 + SM4-GCM）。
 * 追加算法只需实现本接口并装配进 {@link JweCodec}，<b>不改协议</b>。
 *
 * @author changgg
 */
public interface CipherSuite {

    /** 本套件负责的 CEK 封装算法名（与 JWE header 的 {@code alg} 一致）。 */
    Set<String> algorithms();

    /** 本套件负责的内容加密方法名（与 JWE header 的 {@code enc} 一致）。 */
    Set<String> encryptionMethods();

    /**
     * 用服务端私钥解封 CEK。
     *
     * @param alg 报文声明的封装算法（必属 {@link #algorithms()}）
     */
    byte[] unwrapCek(ServerKeyStore keys, String kid, String alg, byte[] encryptedKey) throws Exception;

    /**
     * 带 protected header 的解封入口：ECDH-ES 这类算法要从 header 里取 {@code epk}（临时公钥）。
     *
     * <p>默认实现忽略 header、委托给四参重载；只需要 {@code encrypted_key} 的算法（RSA-OAEP/SM2）无需覆写。</p>
     */
    default byte[] unwrapCek(ServerKeyStore keys, String kid, String alg, byte[] encryptedKey, JWEHeader header)
        throws Exception {
        return unwrapCek(keys, kid, alg, encryptedKey);
    }

    /**
     * AEAD 内容加密。
     *
     * @return 密文与认证标签拼接（{@code cipherText || authTag}），长度 = 明文 + {@link #tagLength(String)}
     */
    byte[] aeadEncrypt(String enc, byte[] cek, byte[] iv, byte[] plaintext, byte[] aad) throws Exception;

    /** AEAD 内容解密（内含 tag 校验；不通过必须抛异常，绝不返回"解出来的明文"）。 */
    byte[] aeadDecrypt(String enc, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag, byte[] aad)
        throws Exception;

    /** 由 {@code enc} 决定的 CEK 字节数（AEAD 密钥长度）。 */
    int keyLength(String enc);

    /** 由 {@code enc} 决定的认证标签字节数（JWE compact 里 tag 是独立一段）。 */
    int tagLength(String enc);

    /**
     * 由 {@code enc} 决定的 IV 字节数。
     *
     * <p>默认 12 字节（AES-GCM / SM4-GCM 的 96-bit IV）。第三方套件若使用其他长度（例如
     * CBC-HMAC 的 16 字节），必须在自己的实现里覆写；{@link JweCodec} 的请求校验与响应
     * IV 生成都以本方法为准。</p>
     */
    default int ivLength(String enc) {
        return 12;
    }
}
