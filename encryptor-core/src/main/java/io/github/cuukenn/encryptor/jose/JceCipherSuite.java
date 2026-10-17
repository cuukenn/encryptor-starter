package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 默认套件：RSA-OAEP-256 封装 CEK + AES-GCM 内容加密（JOSE 标准组合）。
 *
 * <p>全部运算都由 JCE 现算、<b>每次新建 {@link Cipher}</b>（{@code Cipher} 非线程安全，
 * 绝不共享单实例——这是旧实现里 RSA 全局串行的根因）。
 *
 * @author changgg
 */
public class JceCipherSuite implements CipherSuite {

    public static final String ALG = JWEAlgorithm.RSA_OAEP_256.getName();

    private static final Set<String> ALGORITHMS = Collections.unmodifiableSet(
        new LinkedHashSet<>(Collections.singletonList(ALG)));
    private static final Set<String> ENCRYPTION_METHODS = Collections.unmodifiableSet(
        new LinkedHashSet<>(Arrays.asList(EncryptionMethod.A128GCM.getName(), EncryptionMethod.A192GCM.getName(),
            EncryptionMethod.A256GCM.getName())));

    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_TAG_BYTES = 16;

    /**
     * 必须显式指定 {@code OAEPParameterSpec}：裸的 {@code OAEPWithSHA-256AndMGF1Padding} 的 MGF1
     * 默认是 SHA-1，与 JOSE 的 {@code RSA-OAEP-256}（MGF1-SHA-256）不是一回事。
     */
    private static final OAEPParameterSpec OAEP_SPEC = new OAEPParameterSpec("SHA-256", "MGF1",
        MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    @Override
    public Set<String> algorithms() {
        return ALGORITHMS;
    }

    @Override
    public Set<String> encryptionMethods() {
        return ENCRYPTION_METHODS;
    }

    @Override
    public byte[] unwrapCek(ServerKeyStore keys, String kid, String alg, byte[] encryptedKey) throws Exception {
        if (!ALG.equals(alg)) {
            throw JweCodec.fail(EncryptorFailure.ALG_NOT_ALLOWED, "套件不支持的解封算法: " + alg);
        }
        KeyType type = keys.keyType(kid);
        if (type != KeyType.RSA) {
            throw JweCodec.fail(EncryptorFailure.ALG_NOT_ALLOWED,
                "kid=" + kid + " 的密钥类型是 " + type + "，alg=" + ALG + " 需要 RSA 密钥");
        }
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, keys.privateKey(kid), OAEP_SPEC);
        return cipher.doFinal(encryptedKey);
    }

    @Override
    public byte[] aeadEncrypt(String enc, byte[] cek, byte[] iv, byte[] plaintext, byte[] aad) throws Exception {
        checkEnc(enc);
        requireKeyLength(enc, cek);
        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext == null ? new byte[0] : plaintext);
    }

    @Override
    public byte[] aeadDecrypt(String enc, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag, byte[] aad)
        throws Exception {
        checkEnc(enc);
        requireKeyLength(enc, cek);
        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(aad);
        byte[] input = new byte[cipherText.length + authTag.length];
        System.arraycopy(cipherText, 0, input, 0, cipherText.length);
        System.arraycopy(authTag, 0, input, cipherText.length, authTag.length);
        return cipher.doFinal(input);
    }

    @Override
    public int keyLength(String enc) {
        if (EncryptionMethod.A128GCM.getName().equals(enc)) {
            return 16;
        }
        if (EncryptionMethod.A192GCM.getName().equals(enc)) {
            return 24;
        }
        if (EncryptionMethod.A256GCM.getName().equals(enc)) {
            return 32;
        }
        throw JweCodec.fail(EncryptorFailure.ENC_NOT_ALLOWED, "套件不支持的加密方法: " + enc);
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

    private void requireKeyLength(String enc, byte[] cek) {
        if (cek == null || cek.length != keyLength(enc)) {
            throw JweCodec.fail(EncryptorFailure.DECRYPT_FAILED,
                "CEK 长度非法: " + (cek == null ? "null" : cek.length) + "（要求 " + keyLength(enc) + "）");
        }
    }
}
