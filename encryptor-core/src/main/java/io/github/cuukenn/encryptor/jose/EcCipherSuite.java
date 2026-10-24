package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;

import javax.crypto.KeyAgreement;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * ECDH-ES 套件（RFC 7518 §4.6，<b>直接密钥协商</b>）：客户端用临时 EC 密钥对与服务端公钥协商出共享密钥，
 * 经 Concat KDF 派生 CEK；报文里 {@code encrypted_key} 段为空（与 {@code alg=dir} 一样），
 * 服务端靠 protected header 里的 {@code epk} 复算同一把 CEK。
 *
 * <p>只支持 <b>P-256</b>（{@code secp256r1}）：WebCrypto、Java 8 的 SunEC、nimbus 都原生支持，
 * 且不需要引入任何新依赖或注册全局 Provider。曲线不一致一律拒绝（防止降级到弱曲线）。</p>
 *
 * <p>内容加密与 {@link JceCipherSuite} 完全一致（A128/A192/A256-GCM），因此这里直接委托该套件，
 * 避免两份 AEAD 实现；每次仍然新建 {@code Cipher}（线程安全）。</p>
 *
 * <p><b>安全说明</b>：本套件不提供客户端身份认证（临时密钥对是一次性的，任何人都能生成）——
 * 与 RSA/SM2 路径相同，认证交给 TLS + Spring Security。</p>
 *
 * @author changgg
 */
public class EcCipherSuite implements CipherSuite {

    public static final String ALG = "ECDH-ES";

    /** 本实现只接受这一条曲线；{@code epk.crv} 与之不一致即拒绝。 */
    public static final Curve CURVE = Curve.P_256;

    private static final Set<String> ALGORITHMS = Collections.unmodifiableSet(
        new LinkedHashSet<>(Collections.singletonList(ALG)));

    private static final String EPK = "epk";
    private static final String EPK_PRIVATE_PARAM = "d";

    /** AEAD 侧复用 JCE 套件（同一套 AES-GCM 逻辑，避免重复实现）。 */
    private final JceCipherSuite aead = new JceCipherSuite();

    @Override
    public Set<String> algorithms() {
        return ALGORITHMS;
    }

    @Override
    public Set<String> encryptionMethods() {
        return aead.encryptionMethods();
    }

    /**
     * ECDH-ES 必须读 protected header 里的 {@code epk}，四参形态无从取得，一律拒绝。
     */
    @Override
    public byte[] unwrapCek(ServerKeyStore keys, String kid, String alg, byte[] encryptedKey) {
        throw JweCodec.fail(EncryptorFailure.BAD_HEADER,
            "ECDH-ES 需要 protected header 里的 epk，不能走不带 header 的解封入口");
    }

    /** P-256 公钥 x 坐标定长 32 字节（RFC 7518 §4.6.1 的固定宽度约定）。 */
    private static final int P256_COORDINATE_BYTES = 32;
    private static final byte[] EMPTY_BYTES = new byte[0];

    @Override
    public byte[] unwrapCek(ServerKeyStore keys, String kid, String alg, byte[] encryptedKey, JWEHeader header)
        throws Exception {
        // 无 headerJson 的旧入口：现场序列化一次，委托给复用入口
        return unwrapCek(keys, kid, alg, encryptedKey, header, header.toJSONObject());
    }

    @Override
    public byte[] unwrapCek(ServerKeyStore keys, String kid, String alg, byte[] encryptedKey, JWEHeader header,
                            Map<String, Object> headerJson) throws Exception {
        if (!ALG.equals(alg)) {
            throw JweCodec.fail(EncryptorFailure.ALG_NOT_ALLOWED, "套件不支持的解封算法: " + alg);
        }
        KeyType type = keys.keyType(kid);
        if (type != KeyType.EC) {
            throw JweCodec.fail(EncryptorFailure.ALG_NOT_ALLOWED,
                "kid=" + kid + " 的密钥类型是 " + type + "，alg=" + ALG + " 需要 EC(P-256) 密钥");
        }
        if (encryptedKey != null && encryptedKey.length != 0) {
            throw JweCodec.fail(EncryptorFailure.BAD_HEADER,
                "ECDH-ES 是直接密钥协商，encrypted_key 段必须为空");
        }
        if (header == null) {
            throw JweCodec.fail(EncryptorFailure.BAD_HEADER, "ECDH-ES 缺少 protected header");
        }
        rejectPrivateEpk(headerJson);
        com.nimbusds.jose.jwk.JWK epkJwk = header.getEphemeralPublicKey();
        if (!(epkJwk instanceof ECKey)) {
            throw JweCodec.fail(EncryptorFailure.BAD_HEADER, "ECDH-ES 缺少 epk（临时公钥）或它不是 EC 密钥");
        }
        ECKey epk = (ECKey)epkJwk;
        if (!CURVE.equals(epk.getCurve())) {
            throw JweCodec.fail(EncryptorFailure.ALG_NOT_ALLOWED,
                "epk 曲线必须是 " + CURVE.getName() + "，实际: "
                    + (epk.getCurve() == null ? "null" : epk.getCurve().getName()));
        }
        String enc = header.getEncryptionMethod() == null ? null : header.getEncryptionMethod().getName();
        if (enc == null) {
            throw JweCodec.fail(EncryptorFailure.BAD_HEADER, "ECDH-ES 缺少 enc");
        }
        // RFC 7518 §4.6.1：apu/apv 存在时必须进 OtherInfo（PartyUInfo/PartyVInfo）。
        // 此前恒空，与发送 apu/apv 的合规客户端（如 WebCrypto 侧）派生出不同 CEK 而静默失败。
        byte[] partyU = header.getAgreementPartyUInfo() == null
            ? EMPTY_BYTES : header.getAgreementPartyUInfo().decode();
        byte[] partyV = header.getAgreementPartyVInfo() == null
            ? EMPTY_BYTES : header.getAgreementPartyVInfo().decode();
        ECPublicKey ephemeral;
        try {
            ephemeral = epk.toECPublicKey();
        } catch (Exception e) {
            throw JweCodec.fail(EncryptorFailure.BAD_HEADER, "epk 无法解析为 EC 公钥: " + e.getMessage());
        }
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(keys.privateKey(kid));
        agreement.doPhase((PublicKey)ephemeral, true);
        byte[] shared = agreement.generateSecret();
        try {
            // 共享秘密 Z 必须是 P-256 的定长 32 字节 x 坐标：个别 JCE Provider（老版 BC JCA）
            // 会剥掉前导零，导致与服务端/客户端的另一侧派生出不同 CEK——这里统一左补零。
            byte[] z = leftPadTo32(shared);
            try {
                // Concat KDF 的 AlgorithmID 取 enc（RFC 7518 §4.6.2），keydatalen 由 enc 决定
                return ConcatKdf.derive(z, enc, partyU, partyV, keyLength(enc) * 8);
            } finally {
                Arrays.fill(z, (byte) 0);
            }
        } finally {
            // 共享秘密 Z 等价于长期密钥材料，派生完立即清零，不等 GC
            Arrays.fill(shared, (byte) 0);
        }
    }

    /** {@code epk} 是公钥，出现私钥参数 {@code d} 说明客户端实现有问题，直接拒绝。 */
    private static void rejectPrivateEpk(Map<String, Object> headerJson) {
        Object raw = headerJson.get(EPK);
        if (raw instanceof Map && ((Map<?, ?>)raw).containsKey(EPK_PRIVATE_PARAM)) {
            throw JweCodec.fail(EncryptorFailure.BAD_HEADER, "epk 不得携带私钥参数 d");
        }
    }

    /** 共享秘密左补零到 32 字节；超长视为非法（P-256 上不可能）。 */
    private static byte[] leftPadTo32(byte[] shared) {
        if (shared.length == P256_COORDINATE_BYTES) {
            return Arrays.copyOf(shared, shared.length);
        }
        if (shared.length > P256_COORDINATE_BYTES) {
            throw JweCodec.fail(EncryptorFailure.DECRYPT_FAILED,
                "ECDH 共享秘密长度非法: " + shared.length + "（P-256 应为 32 字节）");
        }
        byte[] padded = new byte[P256_COORDINATE_BYTES];
        System.arraycopy(shared, 0, padded, P256_COORDINATE_BYTES - shared.length, shared.length);
        return padded;
    }

    /** CEK 由 ConcatKDF 按 enc 派生，只能配本套件声明的 AES-GCM 家族（拒绝 ECDH-ES + SM4-GCM 等交叉组合）。 */
    @Override
    public boolean pairsWith(String alg, String enc) {
        return ALG.equals(alg) && aead.encryptionMethods().contains(enc);
    }

    @Override
    public byte[] aeadEncrypt(String enc, byte[] cek, byte[] iv, byte[] plaintext, byte[] aad) throws Exception {
        return aead.aeadEncrypt(enc, cek, iv, plaintext, aad);
    }

    @Override
    public byte[] aeadDecrypt(String enc, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag, byte[] aad)
        throws Exception {
        return aead.aeadDecrypt(enc, cek, iv, cipherText, authTag, aad);
    }

    @Override
    public int keyLength(String enc) {
        return aead.keyLength(enc);
    }

    @Override
    public int tagLength(String enc) {
        return aead.tagLength(enc);
    }

    /** 供 JWKS/配置校验使用：本套件要求的曲线名。 */
    public static String curveName() {
        return CURVE.getName();
    }
}
