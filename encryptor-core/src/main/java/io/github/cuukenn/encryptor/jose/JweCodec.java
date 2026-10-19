package io.github.cuukenn.encryptor.jose;

import io.github.cuukenn.encryptor.audit.CompositeEncryptorListener;
import io.github.cuukenn.encryptor.audit.EncryptorListener;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.util.Base64URL;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * JWE 编解码器（请求方向解密、响应方向封装）。
 *
 * <p>顺序不可变：解析 → {@code alg}/{@code enc} 白名单 → {@code kid} → 上下文（AAD）→ 解封 CEK → AEAD 解密（tag 校验）。
 * 白名单在<b>本类内部</b>强制，不可被外部 bean 关掉；集合为空表示"只接受协议默认"（RSA-OAEP-256 / A256GCM）。
 *
 * <p>算法本身不在这里，而在装配进来的 {@link CipherSuite} 里：本类只做"结构 + 顺序 + 白名单 + 分派"，
 * 因此新增算法（例如国密）不需要碰协议与线格式。
 *
 * <p>时间戳与 nonce 的<b>新鲜度</b>校验不在这里（见 {@link ReplayGuard}）：必须先通过 AEAD tag 校验，
 * 否则未认证输入会污染 nonce 存储。
 *
 * @author changgg
 */
public class JweCodec {

    /** 协议默认（也是白名单为空时的唯一允许值）。 */
    public static final String DEFAULT_ALG = JWEAlgorithm.RSA_OAEP_256.getName();
    public static final String DEFAULT_ENC = EncryptionMethod.A256GCM.getName();

    /** AEAD 的标准 IV 长度（GCM 12 字节）。 */
    private static final int IV_LENGTH = 12;

    private final ServerKeyStore keys;
    private final List<CipherSuite> suites;
    private final Set<String> allowedAlgs;
    private final Set<String> allowedEncs;
    private final SecureRandom random = new SecureRandom();
    private final EncryptorListener listener;

    /** 仅装配 JCE 套件（RSA-OAEP-256 + AES-GCM）的便捷构造。 */
    public JweCodec(ServerKeyStore keys, Set<String> allowedAlgs, Set<String> allowedEncs) {
        this(keys, Collections.singletonList(new JceCipherSuite()), allowedAlgs, allowedEncs, EncryptorListener.NONE);
    }

    public JweCodec(ServerKeyStore keys, List<CipherSuite> suites, Set<String> allowedAlgs, Set<String> allowedEncs) {
        this(keys, suites, allowedAlgs, allowedEncs, EncryptorListener.NONE);
    }

    /**
     * @param suites      装配的算法套件（至少一个；白名单只允许取自这里声明的 alg/enc）
     * @param allowedAlgs 允许的封装算法；为空 = 协议默认
     * @param allowedEncs 允许的内容加密方法；为空 = 协议默认
     * @param listener    可观测性回调（成功/失败），可为 {@link EncryptorListener#NONE}；
     *                    监听器异常会记 WARN 并隔离，不改变加解密结果
     */
    public JweCodec(ServerKeyStore keys, List<CipherSuite> suites, Set<String> allowedAlgs, Set<String> allowedEncs,
                    EncryptorListener listener) {
        if (suites == null || suites.isEmpty()) {
            throw new EncryptorException("必须装配至少一个 CipherSuite");
        }
        this.keys = keys;
        this.suites = Collections.unmodifiableList(new ArrayList<>(suites));
        this.allowedAlgs = validate(effective(allowedAlgs, DEFAULT_ALG), installed(true), "alg");
        this.allowedEncs = validate(effective(allowedEncs, DEFAULT_ENC), installed(false), "enc");
        if (listener == null || listener == EncryptorListener.NONE) {
            this.listener = EncryptorListener.NONE;
        } else if (listener instanceof CompositeEncryptorListener) {
            this.listener = listener;
        } else {
            this.listener = CompositeEncryptorListener.of(Collections.singletonList(listener));
        }
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
        try {
            JweContext context = doDecryptRequest(compact, uri, method);
            listener.onDecryptSuccess(context);
            return context;
        } catch (EncryptorException e) {
            listener.onDecryptFailure(e.failure(), e);
            throw e;
        } catch (RuntimeException e) {
            listener.onDecryptFailure(EncryptorFailure.INTERNAL, e);
            throw e;
        }
    }

    private JweContext doDecryptRequest(String compact, String uri, String method) {
        if (compact == null || compact.trim().isEmpty()) {
            throw fail(EncryptorFailure.MISSING, "命中加密范围但报文缺少 jwe 字段");
        }
        String token = compact.trim();
        JWEObject jwe;
        try {
            jwe = JWEObject.parse(token);
        } catch (Exception e) {
            throw new EncryptorException(EncryptorFailure.BAD_HEADER, "JWE 解析失败: " + e.getMessage(), e);
        }

        JWEHeader header = jwe.getHeader();
        if (header == null || header.getAlgorithm() == null || header.getEncryptionMethod() == null
            || jwe.getIV() == null || jwe.getCipherText() == null || jwe.getAuthTag() == null) {
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

        byte[] aad = aadOf(token);
        byte[] iv = jwe.getIV().decode();
        byte[] cipherText = jwe.getCipherText().decode();
        byte[] authTag = jwe.getAuthTag().decode();

        CipherSuite unwrapSuite = suiteOfAlg(alg);
        CipherSuite aeadSuite = suiteOfEnc(enc);
        byte[] cek;
        try {
            // encrypted_key 段对 dir/ECDH-ES 等直接协商类算法为空（nimbus 可能给 null 或空段），
            // 统一成 0 长字节，由套件决定是否接受
            byte[] encryptedKey = jwe.getEncryptedKey() == null ? new byte[0] : jwe.getEncryptedKey().decode();
            cek = unwrapSuite.unwrapCek(keys, kid, alg, encryptedKey, header);
        } catch (EncryptorException e) {
            // 套件已经给出精确分类（如密钥类型与 alg 不匹配 ⇒ ALG_NOT_ALLOWED），不得退化成笼统的解密失败
            throw e;
        } catch (Exception e) {
            throw new EncryptorException(EncryptorFailure.DECRYPT_FAILED, "CEK 解封失败", e);
        }
        if (cek == null || cek.length != aeadSuite.keyLength(enc)) {
            throw fail(EncryptorFailure.DECRYPT_FAILED, "CEK 长度非法");
        }

        byte[] plaintext;
        try {
            plaintext = aeadSuite.aeadDecrypt(enc, cek, iv, cipherText, authTag, aad);
        } catch (Exception e) {
            throw new EncryptorException(EncryptorFailure.DECRYPT_FAILED, "AEAD 校验或解密失败", e);
        }
        return new JweContext(plaintext, cek, kid, alg, enc, ts, nonce);
    }

    /**
     * 封装一个响应报文：{@code alg=dir}，复用请求协商出的 CEK（客户端因此不需要自己的密钥对）。
     *
     * <p>{@code enc} 按 CEK 长度推断（16/24/32 → A128GCM/A192GCM/A256GCM），仅供 AES 路径的便捷调用；
     * 非 AES 套件（例如国密）必须用带 {@code enc} 的重载，显式传入请求协商出的 {@code enc}。
     */
    public String encryptResponse(byte[] body, byte[] cek, String uri, String method, long ts, String nonce) {
        try {
            String enc = cek == null ? null : encOf(cek.length);
            return doEncryptResponse(body, cek, enc, uri, method, ts, nonce);
        } catch (EncryptorException e) {
            listener.onEncryptFailure(e.failure(), e);
            throw e;
        } catch (RuntimeException e) {
            listener.onEncryptFailure(EncryptorFailure.INTERNAL, e);
            throw e;
        }
    }

    /**
     * 封装一个响应报文（{@code alg=dir}，显式指定 {@code enc}）。
     *
     * <p>每次调用生成新的随机 IV；AAD 仍是 protected header（含 {@code dir=res} 与新的 {@code ts}/{@code nonce}），
     * 因此响应密文与"响应方向 + 该 uri/method + 该时刻"绑定，请求密文与之互换必然失败。
     */
    public String encryptResponse(byte[] body, byte[] cek, String enc, String uri, String method, long ts,
                                  String nonce) {
        try {
            return doEncryptResponse(body, cek, enc, uri, method, ts, nonce);
        } catch (EncryptorException e) {
            listener.onEncryptFailure(e.failure(), e);
            throw e;
        } catch (RuntimeException e) {
            listener.onEncryptFailure(EncryptorFailure.INTERNAL, e);
            throw e;
        }
    }

    private String doEncryptResponse(byte[] body, byte[] cek, String enc, String uri, String method, long ts,
                                     String nonce) {
        if (cek == null) {
            throw fail(EncryptorFailure.ENCRYPT_FAILED, "缺少 CEK");
        }
        CipherSuite suite = suiteOfEnc(enc, true);
        if (cek.length != suite.keyLength(enc)) {
            throw fail(EncryptorFailure.ENCRYPT_FAILED, "CEK 长度非法: " + cek.length);
        }
        int tagLength = suite.tagLength(enc);
        try {
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, encMethod(enc))
                .customParams(ContextAad.claims(uri, method, Direction.RESPONSE, ts, nonce))
                .build();
            byte[] aad = header.toBase64URL().toString().getBytes(StandardCharsets.US_ASCII);
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
            byte[] packed = suite.aeadEncrypt(enc, cek, iv, body == null ? new byte[0] : body, aad);
            if (packed.length < tagLength) {
                throw fail(EncryptorFailure.ENCRYPT_FAILED, "AEAD 输出长度非法");
            }
            // 手工拼 compact：protected header . encrypted_key（dir 为空） . iv . cipherText . authTag
            return new String(aad, StandardCharsets.US_ASCII) + "." + "."
                + Base64URL.encode(iv) + "."
                + Base64URL.encode(Arrays.copyOf(packed, packed.length - tagLength)) + "."
                + Base64URL.encode(Arrays.copyOfRange(packed, packed.length - tagLength, packed.length));
        } catch (EncryptorException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptorException(EncryptorFailure.ENCRYPT_FAILED, "响应加密失败: " + e.getMessage(), e);
        }
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

    private CipherSuite suiteOfAlg(String alg) {
        for (CipherSuite suite : suites) {
            if (suite.algorithms().contains(alg)) {
                return suite;
            }
        }
        throw fail(EncryptorFailure.ALG_NOT_ALLOWED, "没有套件支持该 alg: " + alg);
    }

    private CipherSuite suiteOfEnc(String enc) {
        return suiteOfEnc(enc, false);
    }

    /** @param encrypting true 表示响应方向：找不到套件时按 {@code ENCRYPT_FAILED} 报错 */
    private CipherSuite suiteOfEnc(String enc, boolean encrypting) {
        for (CipherSuite suite : suites) {
            if (suite.encryptionMethods().contains(enc)) {
                return suite;
            }
        }
        if (encrypting) {
            throw fail(EncryptorFailure.ENCRYPT_FAILED, "没有套件支持该 enc: " + enc);
        }
        throw fail(EncryptorFailure.ENC_NOT_ALLOWED, "没有套件支持该 enc: " + enc);
    }

    /** 已装配套件声明的 alg / enc（白名单只能取自这里）。 */
    private Set<String> installed(boolean algorithms) {
        Set<String> union = new LinkedHashSet<>();
        for (CipherSuite suite : suites) {
            union.addAll(algorithms ? suite.algorithms() : suite.encryptionMethods());
        }
        return union;
    }

    private static Set<String> effective(Set<String> configured, String fallback) {
        if (configured == null || configured.isEmpty()) {
            return Collections.singleton(fallback);
        }
        return Collections.unmodifiableSet(new LinkedHashSet<>(configured));
    }

    /** 配置里出现没有套件支持的算法一律在构造期失败（fail-fast，不等第一个请求）。 */
    private static Set<String> validate(Set<String> configured, Set<String> installed, String name) {
        for (String value : configured) {
            if (!installed.contains(value)) {
                throw new EncryptorException(
                    "没有套件支持配置的 " + name + ": " + value + "（已装配套件支持 " + installed + "）");
            }
        }
        return configured;
    }

    /** 反向：{@code dir} 下 AES 路径的响应 {@code enc} 由 CEK 长度决定。 */
    private static String encOf(int cekLength) {
        switch (cekLength) {
            case 16:
                return EncryptionMethod.A128GCM.getName();
            case 24:
                return EncryptionMethod.A192GCM.getName();
            case 32:
                return EncryptionMethod.A256GCM.getName();
            default:
                throw fail(EncryptorFailure.ENCRYPT_FAILED, "CEK 长度非法: " + cekLength);
        }
    }

    /** 名字 → nimbus 的 {@link EncryptionMethod}（未注册名也允许：nimbus 会新建实例）。 */
    private static EncryptionMethod encMethod(String enc) {
        try {
            EncryptionMethod parsed = EncryptionMethod.parse(enc);
            if (parsed != null) {
                return parsed;
            }
        } catch (RuntimeException ignored) {
            // 落到下面的构造器
        }
        return new EncryptionMethod(enc);
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

    /** 便捷方法：把 base64url 段解码（供后续任务复用同一套 AAD 规则时使用）。 */
    static byte[] decode(Base64URL value) {
        return value == null ? null : value.decode();
    }

    /** 绑上下文字段名（供后续任务构造/校验 protected header 时复用）。 */
    static Map<String, Object> claims(String uri, String method, Direction direction, long ts, String nonce) {
        return ContextAad.claims(uri, method, direction, ts, nonce);
    }
}
