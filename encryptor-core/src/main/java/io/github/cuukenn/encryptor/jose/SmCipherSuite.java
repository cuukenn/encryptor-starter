package io.github.cuukenn.encryptor.jose;

import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 国密套件：SM2（C1C3C2）封装 CEK + SM4-GCM 内容加密。
 *
 * <p>只用 BouncyCastle <b>轻量级 API</b>（{@link SM2Engine} / {@link GCMBlockCipher}+{@link SM4Engine}），
 * <b>不注册全局 Provider</b>——避免污染应用的 JCA Provider 列表（这是"core 不引 Spring"之外的另一条
 * 不可侵犯约束：库代码不许改进程级状态）。
 *
 * <p>内容加密走 SM4-GCM 而非 SM4-CBC+HMAC-SM3：完整性仍由 AEAD 的 tag 承担，
 * 保持"没有独立 MAC、不做先解密再比较"的协议原则。
 *
 * @author changgg
 */
public class SmCipherSuite implements CipherSuite {

    /** SM2 封装算法名（JOSE 里是私有扩展名，未注册，靠白名单约束）。 */
    public static final String ALG = "SM2";

    /** SM4-GCM 内容加密方法名（同上，私有扩展名）。 */
    public static final String ENC_SM4_GCM = "SM4-GCM";

    private static final Set<String> ALGORITHMS = Collections.unmodifiableSet(
        new LinkedHashSet<>(Collections.singletonList(ALG)));
    private static final Set<String> ENCRYPTION_METHODS = Collections.unmodifiableSet(
        new LinkedHashSet<>(Collections.singletonList(ENC_SM4_GCM)));

    private static final int SM4_KEY_BYTES = 16;
    private static final int GCM_TAG_BYTES = 16;
    private static final int GCM_TAG_BITS = 128;

    private final SecureRandom random = new SecureRandom();

    @Override
    public Set<String> algorithms() {
        return ALGORITHMS;
    }

    @Override
    public Set<String> encryptionMethods() {
        return ENCRYPTION_METHODS;
    }

    /**
     * SM2 解封 CEK：{@code SM2Engine} 的 C1C3C2 模式，输出 {@code C1 || C3 || C2}。
     *
     * @throws io.github.cuukenn.encryptor.exception.EncryptorException 密钥类型与 {@code alg} 不匹配
     *     （分类必须是 {@link EncryptorFailure#ALG_NOT_ALLOWED}，不能退化成笼统的解密失败）
     */
    @Override
    public byte[] unwrapCek(ServerKeyStore keys, String kid, String alg, byte[] encryptedKey) throws Exception {
        if (!ALG.equals(alg)) {
            throw JweCodec.fail(EncryptorFailure.ALG_NOT_ALLOWED, "套件不支持的解封算法: " + alg);
        }
        KeyType type = keys.keyType(kid);
        if (type != KeyType.SM2) {
            throw JweCodec.fail(EncryptorFailure.ALG_NOT_ALLOWED,
                "kid=" + kid + " 的密钥类型是 " + type + "，alg=" + ALG + " 需要 SM2 密钥");
        }
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keys.sm2PrivateKey(kid);
        SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        engine.init(false, privateKey);
        return engine.processBlock(encryptedKey, 0, encryptedKey.length);
    }

    @Override
    public byte[] aeadEncrypt(String enc, byte[] cek, byte[] iv, byte[] plaintext, byte[] aad) throws Exception {
        checkEnc(enc);
        requireKeyLength(enc, cek);
        byte[] input = plaintext == null ? new byte[0] : plaintext;
        GCMBlockCipher cipher = new GCMBlockCipher(new SM4Engine());
        cipher.init(true, new AEADParameters(new KeyParameter(cek), GCM_TAG_BITS, iv, aadOrEmpty(aad)));
        byte[] out = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.processBytes(input, 0, input.length, out, 0);
        cipher.doFinal(out, len);
        return out;
    }

    /** 输入是 {@code cipherText || authTag}（GCM 的原生排布），输出明文；tag 不符抛分类明确的失败。 */
    @Override
    public byte[] aeadDecrypt(String enc, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag, byte[] aad)
        throws Exception {
        checkEnc(enc);
        requireKeyLength(enc, cek);
        byte[] input = new byte[cipherText.length + authTag.length];
        System.arraycopy(cipherText, 0, input, 0, cipherText.length);
        System.arraycopy(authTag, 0, input, cipherText.length, authTag.length);
        GCMBlockCipher cipher = new GCMBlockCipher(new SM4Engine());
        cipher.init(false, new AEADParameters(new KeyParameter(cek), GCM_TAG_BITS, iv, aadOrEmpty(aad)));
        byte[] out = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.processBytes(input, 0, input.length, out, 0);
        try {
            cipher.doFinal(out, len);
        } catch (InvalidCipherTextException e) {
            throw JweCodec.fail(EncryptorFailure.DECRYPT_FAILED, "SM4-GCM 认证标签校验失败: " + e.getMessage());
        }
        return out;
    }

    @Override
    public int keyLength(String enc) {
        checkEnc(enc);
        return SM4_KEY_BYTES;
    }

    @Override
    public int tagLength(String enc) {
        checkEnc(enc);
        return GCM_TAG_BYTES;
    }

    private static void checkEnc(String enc) {
        if (!ENCRYPTION_METHODS.contains(enc)) {
            throw JweCodec.fail(EncryptorFailure.ENC_NOT_ALLOWED, "套件不支持的加密方法: " + enc);
        }
    }

    private static void requireKeyLength(String enc, byte[] cek) {
        if (cek == null || cek.length != SM4_KEY_BYTES) {
            throw JweCodec.fail(EncryptorFailure.DECRYPT_FAILED,
                "CEK 长度非法: " + (cek == null ? "null" : cek.length) + "（要求 " + SM4_KEY_BYTES + "）");
        }
    }

    private static byte[] aadOrEmpty(byte[] aad) {
        return aad == null ? new byte[0] : aad;
    }
}
