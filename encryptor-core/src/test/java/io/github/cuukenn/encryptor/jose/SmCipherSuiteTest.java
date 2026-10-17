package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.util.Base64URL;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link SmCipherSuite} 契约测试：SM2 封装 CEK + SM4-GCM 内容加密（国密路径）。
 *
 * <p>夹具一律用 <b>BC 轻量级 API 裸写</b>（不经 {@link SmCipherSuite}），这样"套件把 C1C3C2/标签位置搞反
 * 而测试跟着一起错"的对称性缺陷钉不出来。
 *
 * @author changgg
 */
class SmCipherSuiteTest {

    private static final int GCM_TAG_BYTES = 16;
    private static final int SM4_KEY_BYTES = 16;
    private static final OAEPParameterSpec OAEP_SPEC = new OAEPParameterSpec("SHA-256", "MGF1",
        MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    // ------------------------------------------------------------------ 夹具

    /** 现场生成一对 EC 密钥（{@code curve} 例如 {@code sm2p256v1}、{@code P-256}）。 */
    private static AsymmetricCipherKeyPair newEcKeyPair(String curve) {
        org.bouncycastle.asn1.x9.X9ECParameters params = CustomNamedCurves.getByName(curve);
        ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(),
            params.getH());
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(domain, new SecureRandom()));
        return generator.generateKeyPair();
    }

    private static String privPkcs8Base64(AsymmetricCipherKeyPair pair) throws Exception {
        return Base64.getEncoder().encodeToString(
            PrivateKeyInfoFactory.createPrivateKeyInfo(pair.getPrivate()).getEncoded(ASN1Encoding.DER));
    }

    private static String pubSpkiBase64(AsymmetricCipherKeyPair pair) throws Exception {
        return Base64.getEncoder().encodeToString(
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pair.getPublic()).getEncoded(ASN1Encoding.DER));
    }

    private static ServerKeyStore sm2Store(String kid) throws Exception {
        AsymmetricCipherKeyPair pair = newEcKeyPair("sm2p256v1");
        return ServerKeyStore.builder().add(kid, privPkcs8Base64(pair), pubSpkiBase64(pair), KeyType.SM2)
            .activeKid(kid).build();
    }

    /** 客户端视角：SM2(C1C3C2) 封装一段数据 —— 与套件实现无关的独立写法。 */
    private static byte[] sm2EncryptRaw(ECPublicKeyParameters publicKey, byte[] plaintext)
        throws org.bouncycastle.crypto.InvalidCipherTextException {
        SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        engine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));
        return engine.processBlock(plaintext, 0, plaintext.length);
    }

    /** 客户端视角：SM4-GCM 内容加密，返回 cipherText‖authTag —— 与套件实现无关的独立写法。 */
    private static byte[] sm4GcmEncryptRaw(byte[] cek, byte[] iv, byte[] plaintext, byte[] aad)
        throws org.bouncycastle.crypto.InvalidCipherTextException {
        GCMBlockCipher cipher = new GCMBlockCipher(new SM4Engine());
        cipher.init(true, new AEADParameters(new KeyParameter(cek), GCM_TAG_BYTES * 8, iv, aad));
        return process(cipher, plaintext);
    }

    /** 客户端视角：RSA-OAEP-256 封装 CEK（走 JCE，与 JceCipherSuite 同构但独立写）。 */
    private static byte[] rsaOaepEncryptRaw(java.security.PublicKey publicKey, byte[] cek) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_SPEC);
        return cipher.doFinal(cek);
    }

    /** 客户端视角：AES-GCM 内容加密，返回 cipherText‖authTag。 */
    private static byte[] aesGcmEncryptRaw(byte[] cek, byte[] iv, byte[] plaintext, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(GCM_TAG_BYTES * 8, iv));
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    private static byte[] process(GCMBlockCipher cipher, byte[] plaintext)
        throws org.bouncycastle.crypto.InvalidCipherTextException {
        byte[] out = new byte[cipher.getOutputSize(plaintext.length)];
        int len = cipher.processBytes(plaintext, 0, plaintext.length, out, 0);
        cipher.doFinal(out, len);
        return out;
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static EncryptionMethod encMethod(String name) {
        try {
            EncryptionMethod method = EncryptionMethod.parse(name);
            if (method != null) {
                return method;
            }
        } catch (RuntimeException ignored) {
            // 落到构造器
        }
        return new EncryptionMethod(name);
    }

    private static String compact(JWEHeader header, byte[] encryptedKey, byte[] iv, byte[] packed, int tagLength) {
        byte[] cipherText = Arrays.copyOf(packed, packed.length - tagLength);
        byte[] authTag = Arrays.copyOfRange(packed, packed.length - tagLength, packed.length);
        return header.toBase64URL() + "."
            + Base64URL.encode(encryptedKey) + "."
            + Base64URL.encode(iv) + "."
            + Base64URL.encode(cipherText) + "."
            + Base64URL.encode(authTag);
    }

    private static JWEHeader requestHeader(String alg, String enc, String kid, String uri, String method, long ts,
                                           String nonce) {
        return new JWEHeader.Builder(JWEAlgorithm.parse(alg), encMethod(enc))
            .keyID(kid)
            .customParams(ContextAad.claims(uri, method, Direction.REQUEST, ts, nonce))
            .build();
    }

    // ------------------------------------------------------------------ 用例

    @Test
    void SM2封装解封往返并钉住C1C3C2排列() throws Exception {
        AsymmetricCipherKeyPair pair = newEcKeyPair("sm2p256v1");
        ServerKeyStore keys = ServerKeyStore.builder()
            .add("sm2-1", privPkcs8Base64(pair), pubSpkiBase64(pair), KeyType.SM2)
            .activeKid("sm2-1").build();

        byte[] cek = randomBytes(SM4_KEY_BYTES);
        byte[] encryptedKey = sm2EncryptRaw((ECPublicKeyParameters) pair.getPublic(), cek);

        // 钉住线格式：C1(65 字节，04 前缀) || C3(32 字节) || C2(16 字节 CEK)
        assertEquals(65 + 32 + SM4_KEY_BYTES, encryptedKey.length, "SM2 密文应为 C1||C3||C2");
        assertEquals(0x04, encryptedKey[0] & 0xFF, "C1 必须是未压缩点 04||x||y");

        byte[] unwrapped = new SmCipherSuite().unwrapCek(keys, "sm2-1", "SM2", encryptedKey);
        assertArrayEquals(cek, unwrapped, "解封结果必须与客户端封装的 CEK 一致");
    }

    @Test
    void SM4GCM往返并钉住密文与tag分段() throws Exception {
        SmCipherSuite suite = new SmCipherSuite();
        assertEquals(SM4_KEY_BYTES, suite.keyLength("SM4-GCM"));
        assertEquals(GCM_TAG_BYTES, suite.tagLength("SM4-GCM"));

        byte[] cek = randomBytes(SM4_KEY_BYTES);
        byte[] iv = randomBytes(12);
        byte[] aad = "header-segment".getBytes(StandardCharsets.US_ASCII);
        byte[] plaintext = "国密 SM4-GCM 往返报文".getBytes(StandardCharsets.UTF_8);

        byte[] packed = suite.aeadEncrypt("SM4-GCM", cek, iv, plaintext, aad);
        assertEquals(plaintext.length + GCM_TAG_BYTES, packed.length, "输出必须是 cipherText‖authTag");

        byte[] cipherText = Arrays.copyOf(packed, packed.length - GCM_TAG_BYTES);
        byte[] authTag = Arrays.copyOfRange(packed, packed.length - GCM_TAG_BYTES, packed.length);
        assertArrayEquals(plaintext, suite.aeadDecrypt("SM4-GCM", cek, iv, cipherText, authTag, aad));
    }

    @Test
    void 篡改密文或tag或AAD一律解密失败() throws Exception {
        AsymmetricCipherKeyPair pair = newEcKeyPair("sm2p256v1");
        ServerKeyStore keys = ServerKeyStore.builder()
            .add("sm2-1", privPkcs8Base64(pair), pubSpkiBase64(pair), KeyType.SM2).activeKid("sm2-1").build();
        JweCodec codec = dualSuiteCodec(keys);

        byte[] cek = randomBytes(SM4_KEY_BYTES);
        byte[] iv = randomBytes(12);
        byte[] plaintext = "{\"amount\":1}".getBytes(StandardCharsets.UTF_8);
        JWEHeader header = requestHeader("SM2", "SM4-GCM", "sm2-1", "/api/pay", "POST", 1729100000000L, "n-1");
        byte[] aad = header.toBase64URL().toString().getBytes(StandardCharsets.US_ASCII);
        byte[] encryptedKey = sm2EncryptRaw((ECPublicKeyParameters) pair.getPublic(), cek);
        byte[] packed = sm4GcmEncryptRaw(cek, iv, plaintext, aad);
        String token = compact(header, encryptedKey, iv, packed, GCM_TAG_BYTES);

        JweContext context = codec.decryptRequest(token, "/api/pay", "POST");
        assertArrayEquals(plaintext, context.plaintext());

        // 改密文
        String[] parts = token.split("\\.");
        byte[] cipherText = Base64.getUrlDecoder().decode(parts[3]);
        cipherText[0] ^= 0x01;
        String tamperedCipherText = parts[0] + "." + parts[1] + "." + parts[2] + "."
            + Base64URL.encode(cipherText) + "." + parts[4];
        EncryptorException e1 = assertThrows(EncryptorException.class,
            () -> codec.decryptRequest(tamperedCipherText, "/api/pay", "POST"));
        assertEquals(EncryptorFailure.DECRYPT_FAILED, e1.failure(), "改密文必须是 AEAD 校验失败");

        // 改 tag
        byte[] authTag = Base64.getUrlDecoder().decode(parts[4]);
        authTag[0] ^= 0x01;
        String tamperedTag = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3] + "."
            + Base64URL.encode(authTag);
        EncryptorException e2 = assertThrows(EncryptorException.class,
            () -> codec.decryptRequest(tamperedTag, "/api/pay", "POST"));
        assertEquals(EncryptorFailure.DECRYPT_FAILED, e2.failure(), "改 tag 必须是 AEAD 校验失败");

        // 改 protected header 里的 uri（AAD 被篡改）
        String tamperedUri = compact(requestHeader("SM2", "SM4-GCM", "sm2-1", "/api/other", "POST",
            1729100000000L, "n-1"), encryptedKey, iv, packed, GCM_TAG_BYTES);
        EncryptorException e3 = assertThrows(EncryptorException.class,
            () -> codec.decryptRequest(tamperedUri, "/api/pay", "POST"));
        assertEquals(EncryptorFailure.AAD_MISMATCH, e3.failure(), "改 uri 必须是 AAD 不匹配");
    }

    @Test
    void 端到端_双套件装配_SM2与RSA请求都能解且响应可用SM4回包() throws Exception {
        AsymmetricCipherKeyPair pair = newEcKeyPair("sm2p256v1");
        String[] rsaKeys = newRsaKeyPair();
        ServerKeyStore keys = ServerKeyStore.builder()
            .add("rsa-1", rsaKeys[0], rsaKeys[1])
            .add("sm2-1", privPkcs8Base64(pair), pubSpkiBase64(pair), KeyType.SM2)
            .activeKid("sm2-1").build();
        JweCodec codec = dualSuiteCodec(keys);

        // 1) 国密请求
        byte[] cek = randomBytes(SM4_KEY_BYTES);
        byte[] iv = randomBytes(12);
        byte[] plaintext = "国密端到端".getBytes(StandardCharsets.UTF_8);
        JWEHeader header = requestHeader("SM2", "SM4-GCM", "sm2-1", "/api/x", "POST", 1729100000000L, "n-2");
        byte[] aad = header.toBase64URL().toString().getBytes(StandardCharsets.US_ASCII);
        byte[] encryptedKey = sm2EncryptRaw((ECPublicKeyParameters) pair.getPublic(), cek);
        byte[] packed = sm4GcmEncryptRaw(cek, iv, plaintext, aad);
        JweContext sm2Context = codec.decryptRequest(compact(header, encryptedKey, iv, packed, GCM_TAG_BYTES),
            "/api/x", "POST");
        assertArrayEquals(plaintext, sm2Context.plaintext());
        assertEquals("SM2", sm2Context.alg());
        assertEquals("SM4-GCM", sm2Context.enc());
        assertEquals("sm2-1", sm2Context.kid());
        assertArrayEquals(cek, sm2Context.cek());

        // 2) 同一个 codec 下 RSA 请求照样能解（双套件共存）
        byte[] rsaCek = randomBytes(32);
        byte[] rsaIv = randomBytes(12);
        byte[] rsaPlaintext = "rsa-path".getBytes(StandardCharsets.UTF_8);
        JWEHeader rsaHeader = requestHeader("RSA-OAEP-256", "A256GCM", "rsa-1", "/api/x", "POST", 1729100000000L,
            "n-3");
        byte[] rsaAad = rsaHeader.toBase64URL().toString().getBytes(StandardCharsets.US_ASCII);
        byte[] rsaEncryptedKey = rsaOaepEncryptRaw(keys.publicKey("rsa-1"), rsaCek);
        byte[] rsaPacked = aesGcmEncryptRaw(rsaCek, rsaIv, rsaPlaintext, rsaAad);
        JweContext rsaContext = codec.decryptRequest(
            compact(rsaHeader, rsaEncryptedKey, rsaIv, rsaPacked, GCM_TAG_BYTES), "/api/x", "POST");
        assertArrayEquals(rsaPlaintext, rsaContext.plaintext());

        // 3) 用国密请求协商出的 CEK + 请求的 enc 回包，客户端能用同一 CEK 解开
        String response = codec.encryptResponse("OK".getBytes(StandardCharsets.UTF_8), sm2Context.cek(),
            sm2Context.enc(), "/api/x", "POST", 1729100006000L, "n-4");
        String[] responseParts = response.split("\\.", -1);
        assertEquals(5, responseParts.length);
        assertEquals("", responseParts[1], "alg=dir 的 encrypted_key 段必须为空");
        byte[] responseAad = responseParts[0].getBytes(StandardCharsets.US_ASCII);
        byte[] responseIv = Base64.getUrlDecoder().decode(responseParts[2]);
        byte[] responseCipherText = Base64.getUrlDecoder().decode(responseParts[3]);
        byte[] responseTag = Base64.getUrlDecoder().decode(responseParts[4]);
        byte[] recovered = new SmCipherSuite().aeadDecrypt("SM4-GCM", sm2Context.cek(), responseIv,
            responseCipherText, responseTag, responseAad);
        assertEquals("OK", new String(recovered, StandardCharsets.UTF_8));
    }

    @Test
    void 密钥类型与alg不匹配时分类为ALG_NOT_ALLOWED() throws Exception {
        String[] rsaKeys = newRsaKeyPair();
        AsymmetricCipherKeyPair pair = newEcKeyPair("sm2p256v1");
        ServerKeyStore keys = ServerKeyStore.builder()
            .add("rsa-1", rsaKeys[0], rsaKeys[1])
            .add("sm2-1", privPkcs8Base64(pair), pubSpkiBase64(pair), KeyType.SM2)
            .build();
        JweCodec codec = dualSuiteCodec(keys);

        // kid 是 RSA 密钥，alg 却声称 SM2
        byte[] cek = randomBytes(SM4_KEY_BYTES);
        byte[] iv = randomBytes(12);
        JWEHeader header = requestHeader("SM2", "SM4-GCM", "rsa-1", "/api/x", "POST", 1729100000000L, "n-5");
        byte[] aad = header.toBase64URL().toString().getBytes(StandardCharsets.US_ASCII);
        byte[] garbage = randomBytes(97 + 16);
        byte[] packed = sm4GcmEncryptRaw(cek, iv, "x".getBytes(StandardCharsets.UTF_8), aad);
        EncryptorException e = assertThrows(EncryptorException.class, () -> codec.decryptRequest(
            compact(header, garbage, iv, packed, GCM_TAG_BYTES), "/api/x", "POST"));
        assertEquals(EncryptorFailure.ALG_NOT_ALLOWED, e.failure(),
            "密钥类型与 alg 不匹配必须精确分类，而不是笼统的 DECRYPT_FAILED");
    }

    @Test
    void RSA算法配SM2密钥时分类为ALG_NOT_ALLOWED() throws Exception {
        AsymmetricCipherKeyPair pair = newEcKeyPair("sm2p256v1");
        ServerKeyStore keys = ServerKeyStore.builder()
            .add("sm2-1", privPkcs8Base64(pair), pubSpkiBase64(pair), KeyType.SM2)
            .build();
        JweCodec codec = dualSuiteCodec(keys);

        byte[] cek = randomBytes(32);
        byte[] iv = randomBytes(12);
        JWEHeader header = requestHeader("RSA-OAEP-256", "A256GCM", "sm2-1", "/api/x", "POST", 1729100000000L, "n-6");
        byte[] aad = header.toBase64URL().toString().getBytes(StandardCharsets.US_ASCII);
        byte[] encryptedKey = randomBytes(256);
        byte[] packed = aesGcmEncryptRaw(cek, iv, "x".getBytes(StandardCharsets.UTF_8), aad);
        EncryptorException e = assertThrows(EncryptorException.class, () -> codec.decryptRequest(
            compact(header, encryptedKey, iv, packed, GCM_TAG_BYTES), "/api/x", "POST"));
        assertEquals(EncryptorFailure.ALG_NOT_ALLOWED, e.failure(),
            "RSA 算法配 SM2 密钥必须是密钥类型不匹配，而不是笼统的 DECRYPT_FAILED");
    }

    @Test
    void 不在白名单的enc拒绝构造或请求() throws Exception {
        AsymmetricCipherKeyPair pair = newEcKeyPair("sm2p256v1");
        ServerKeyStore keys = ServerKeyStore.builder()
            .add("sm2-1", privPkcs8Base64(pair), pubSpkiBase64(pair), KeyType.SM2).activeKid("sm2-1").build();

        // 构造期：配置里出现没有套件支持的 enc ⇒ fail-fast
        assertThrows(EncryptorException.class, () -> new JweCodec(keys,
            Arrays.asList(new JceCipherSuite(), new SmCipherSuite()),
            new LinkedHashSet<>(Arrays.asList("SM2")),
            new LinkedHashSet<>(Arrays.asList("A256GCM", "RC4"))));
    }

    // ------------------------------------------------------------------ 辅助

    private static JweCodec dualSuiteCodec(ServerKeyStore keys) {
        return new JweCodec(keys, Arrays.asList(new JceCipherSuite(), new SmCipherSuite()),
            new LinkedHashSet<>(Arrays.asList("RSA-OAEP-256", "SM2")),
            new LinkedHashSet<>(Arrays.asList("A256GCM", "A128GCM", "A192GCM", "SM4-GCM")));
    }

    private static String[] newRsaKeyPair() throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        java.security.KeyPair keyPair = generator.generateKeyPair();
        return new String[] {
            Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()),
            Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
        };
    }
}
