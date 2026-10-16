package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.util.Base64URL;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * JWE 编解码器（请求方向：解密）。
 *
 * <p>顺序不可变：解析 → {@code alg}/{@code enc} 白名单 → {@code kid} → 上下文（AAD）→ 解封 CEK → AES-GCM 解密（tag 校验）。
 * 白名单在<b>本类内部</b>强制，不可被外部 bean 关掉；集合为空表示"只接受协议默认"（RSA-OAEP-256 / A256GCM）。
 *
 * <p>时间戳与 nonce 的<b>新鲜度</b>校验不在这里（见 T5 {@code ReplayGuard}）：必须先通过 GCM tag 校验，
 * 否则未认证输入会污染 nonce 存储。
 *
 * @author changgg
 */
public class JweCodec {

    /** 协议默认（也是白名单为空时的唯一允许值）。 */
    public static final String DEFAULT_ALG = JWEAlgorithm.RSA_OAEP_256.getName();
    public static final String DEFAULT_ENC = EncryptionMethod.A256GCM.getName();

    /** 本实现支持的内容加密方法（均为 AEAD 的 GCM 家族）。 */
    private static final Set<String> SUPPORTED_ENCS = Collections.unmodifiableSet(
        new LinkedHashSet<>(java.util.Arrays.asList(EncryptionMethod.A256GCM.getName(),
            EncryptionMethod.A192GCM.getName(), EncryptionMethod.A128GCM.getName())));
    /** 本实现支持的密钥封装算法（只有 RSA-OAEP-256）。 */
    private static final Set<String> SUPPORTED_ALGS = Collections.singleton(DEFAULT_ALG);

    private static final int GCM_TAG_BITS = 128;

    private final ServerKeyStore keys;
    private final Set<String> allowedAlgs;
    private final Set<String> allowedEncs;

    public JweCodec(ServerKeyStore keys, Set<String> allowedAlgs, Set<String> allowedEncs) {
        this.keys = keys;
        this.allowedAlgs = validate(effective(allowedAlgs, DEFAULT_ALG), SUPPORTED_ALGS, "alg");
        this.allowedEncs = validate(effective(allowedEncs, DEFAULT_ENC), SUPPORTED_ENCS, "enc");
    }

    /**
     * 解密一个请求报文。
     *
     * @param compact JWE Compact 序列化（{@code ?jwe=} 或 body 里 {@code jwe} 字段的值）
     * @param uri     {@link ContextAad#canonicalPath} 规范化后的路径
     * @param method  HTTP 方法
     * @throws EncryptorException 带 {@link EncryptorFailure} 分类
     */
    public JweContext decryptRequest(String compact, String uri, String method) {
        if (compact == null || compact.trim().isEmpty()) {
            throw fail(EncryptorFailure.MISSING, "命中加密范围但报文缺少 jwe 字段");
        }
        JWEObject jwe;
        try {
            jwe = JWEObject.parse(compact.trim());
        } catch (Exception e) {
            throw new EncryptorException(EncryptorFailure.BAD_HEADER, "JWE 解析失败: " + e.getMessage(), e);
        }

        JWEHeader header = jwe.getHeader();
        if (header == null || header.getAlgorithm() == null || header.getEncryptionMethod() == null
            || jwe.getIV() == null || jwe.getCipherText() == null || jwe.getAuthTag() == null
            || jwe.getEncryptedKey() == null) {
            throw fail(EncryptorFailure.BAD_HEADER, "JWE 结构不完整");
        }
        String alg = header.getAlgorithm().getName();
        String enc = header.getEncryptionMethod().getName();
        if (!allowedAlgs.contains(alg)) {
            throw fail(EncryptorFailure.ALG_NOT_ALLOWED, "alg 不在白名单: " + alg);
        }
        if (!allowedEncs.contains(enc)) {
            throw fail(EncryptorFailure.ENC_NOT_ALLOWED, "enc 不在白名单: " + enc);
        }

        String kid = header.getKeyID();
        if (kid == null || !keys.contains(kid)) {
            throw fail(EncryptorFailure.UNKNOWN_KID, "未知或缺失的 kid: " + kid);
        }

        try {
            ContextAad.verify(header.toJSONObject(), uri, method, Direction.REQUEST);
        } catch (EncryptorException e) {
            throw new EncryptorException(EncryptorFailure.AAD_MISMATCH, e.getMessage(), e);
        }

        Long ts = longParam(header, ContextAad.CLAIM_TS);
        String nonce = stringParam(header, ContextAad.CLAIM_NONCE);
        if (ts == null || nonce == null || nonce.isEmpty()) {
            throw fail(EncryptorFailure.BAD_HEADER, "绑上下文缺少 ts/nonce");
        }

        byte[] aad = aadOf(compact.trim());
        byte[] iv = jwe.getIV().decode();
        byte[] cipherText = jwe.getCipherText().decode();
        byte[] authTag = jwe.getAuthTag().decode();

        byte[] cek;
        try {
            cek = unwrapCek(kid, jwe.getEncryptedKey().decode());
        } catch (Exception e) {
            throw new EncryptorException(EncryptorFailure.DECRYPT_FAILED, "CEK 解封失败", e);
        }
        if (cek == null || cek.length != cekLength(enc)) {
            throw fail(EncryptorFailure.DECRYPT_FAILED, "CEK 长度非法");
        }

        byte[] plaintext;
        try {
            plaintext = gcmDecrypt(cek, iv, cipherText, authTag, aad);
        } catch (Exception e) {
            throw new EncryptorException(EncryptorFailure.DECRYPT_FAILED, "AEAD 校验或解密失败", e);
        }
        return new JweContext(plaintext, cek, kid, alg, enc, ts, nonce);
    }

    /** 构造带分类的失败异常（供本包与后续任务复用）。 */
    public static EncryptorException fail(EncryptorFailure failure, String message) {
        return new EncryptorException(failure, message);
    }

    /**
     * RFC 7516：Compact 序列化没有独立 AAD 字段，AAD 就是 {@code ASCII(BASE64URL(protected header))}，
     * 即 compact 的第一段。
     */
    static byte[] aadOf(String compact) {
        int index = compact.indexOf('.');
        String protectedHeader = index < 0 ? compact : compact.substring(0, index);
        return protectedHeader.getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * RSA-OAEP-256 解封 CEK。
     *
     * <p>不走 nimbus 的 {@code RSADecrypter}：它对"密钥封装"类算法会连同内容一起解、返回的是<b>明文</b>本身，
     * 而我们需要 CEK 原值来加密响应（{@code alg=dir}）。这里用 JCE 显式指定 {@code OAEPParameterSpec}，
     * 因为裸的 {@code OAEPWithSHA-256AndMGF1Padding} 的 MGF1 默认是 SHA-1，与 JOSE 的 RSA-OAEP-256 不符。
     * 每次调用新建 {@code Cipher}（非线程安全，绝不共享单实例）。
     */
    private byte[] unwrapCek(String kid, byte[] encryptedKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, keys.privateKey(kid), new OAEPParameterSpec("SHA-256", "MGF1",
            MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        return cipher.doFinal(encryptedKey);
    }

    static byte[] gcmDecrypt(byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag, byte[] aad)
        throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(aad);
        byte[] input = new byte[cipherText.length + authTag.length];
        System.arraycopy(cipherText, 0, input, 0, cipherText.length);
        System.arraycopy(authTag, 0, input, cipherText.length, authTag.length);
        return cipher.doFinal(input);
    }

    private static Set<String> effective(Set<String> configured, String fallback) {
        if (configured == null || configured.isEmpty()) {
            return Collections.singleton(fallback);
        }
        return Collections.unmodifiableSet(new LinkedHashSet<>(configured));
    }

    /** 配置里出现本实现不支持的算法一律在构造期失败（fail-fast，不等第一个请求）。 */
    private static Set<String> validate(Set<String> configured, Set<String> supported, String name) {
        for (String value : configured) {
            if (!supported.contains(value)) {
                throw new EncryptorException("暂不支持的 " + name + ": " + value + "（当前仅支持 " + supported + "）");
            }
        }
        return configured;
    }

    /** AEAD 密钥长度由 {@code enc} 决定。 */
    private static int cekLength(String enc) {
        if (EncryptionMethod.A128GCM.getName().equals(enc)) {
            return 16;
        }
        if (EncryptionMethod.A192GCM.getName().equals(enc)) {
            return 24;
        }
        return 32;
    }

    private static Long longParam(JWEHeader header, String name) {
        Object value = header.getCustomParam(name);
        if (value instanceof Number) {
            return ((Number)value).longValue();
        }
        if (value instanceof String) {
            try {
                return Long.parseLong((String)value);
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static String stringParam(JWEHeader header, String name) {
        Object value = header.getCustomParam(name);
        return value == null ? null : String.valueOf(value);
    }

    /** 便捷方法：把 base64url 段解码（供 T4 复用同一套 AAD 规则时使用）。 */
    static byte[] decode(Base64URL value) {
        return value == null ? null : value.decode();
    }
}
