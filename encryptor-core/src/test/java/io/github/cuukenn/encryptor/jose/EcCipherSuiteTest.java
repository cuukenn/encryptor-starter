package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.util.Base64URL;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ECDH-ES（P-256，直接密钥协商）用例。
 *
 * <p>关键点：客户端侧一律用 <b>nimbus 自己的 {@link ECDHEncrypter}</b>（独立实现：它自己做 ECDH + Concat KDF +
 * 生成 {@code epk}），服务端用本项目的 {@link EcCipherSuite} 解；响应再用 nimbus 的 {@link DirectDecrypter} 解。
 * 两边只要有一处 KDF/字段不一致就会失败，因此这组用例等价于一次跨实现互通验证。</p>
 */
class EcCipherSuiteTest {

    private static final String URI = "/api/ec";
    private static final String METHOD = "POST";
    private static final long TS = 1730000000000L;
    private static final String NONCE = "n-ec-1";

    // ---------------------------------------------------------------- 正向：跨实现往返

    @Test
    void nimbus独立实现加密_我方解密并回加密() throws Exception {
        KeyPair server = p256();
        JweCodec codec = new JweCodec(store("ec-1", server),
            Collections.singletonList(new EcCipherSuite()),
            Collections.singleton("ECDH-ES"), Collections.singleton("A256GCM"));

        byte[] request = "{\"hi\":\"ecdh-es\"}".getBytes(StandardCharsets.UTF_8);
        JWEObject jwe = new JWEObject(requestHeader(), new Payload(request));
        jwe.encrypt(new ECDHEncrypter((ECPublicKey)server.getPublic()));

        JweContext context = codec.decryptRequest(jwe.serialize(), URI, METHOD);
        assertArrayEquals(request, context.plaintext());
        assertEquals("ECDH-ES", context.alg());
        assertEquals("A256GCM", context.enc());
        assertEquals("ec-1", context.kid());
        assertEquals(32, context.cek().length, "A256GCM 派生出的 CEK 必须 32 字节");

        byte[] response = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
        JWEObject back = JWEObject.parse(codec.encryptResponse(response, context.cek(), "A256GCM",
            URI, METHOD, TS, NONCE));
        assertEquals(JWEAlgorithm.DIR, back.getHeader().getAlgorithm());
        back.decrypt(new DirectDecrypter(new SecretKeySpec(context.cek(), "AES")));
        assertArrayEquals(response, back.getPayload().toBytes());
    }

    @Test
    void 派生密钥随enc长度变化() throws Exception {
        KeyPair server = p256();
        byte[] z = new byte[32];
        Arrays.fill(z, (byte)7);
        assertEquals(16, ConcatKdf.derive(z, "A128GCM", 128).length);
        assertEquals(24, ConcatKdf.derive(z, "A192GCM", 192).length);
        assertEquals(32, ConcatKdf.derive(z, "A256GCM", 256).length);
        assertNotNull(server);
    }

    @Test
    void nimbus携带apu_apv也能互通() throws Exception {
        // RFC 7518 §4.6.1：apu/apv 存在时必须进 OtherInfo。此前恒空，带 apu/apv 的合规客户端
        // 会派生出不同 CEK 而静默失败；这里用 nimbus 独立实现（会按 RFC 把 apu/apv 参与 KDF）对拍
        KeyPair server = p256();
        JweCodec codec = new JweCodec(store("ec-1", server),
            Collections.singletonList(new EcCipherSuite()),
            Collections.singleton("ECDH-ES"), Collections.singleton("A256GCM"));

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.parse(EcCipherSuite.ALG), EncryptionMethod.A256GCM)
            .keyID("ec-1")
            .agreementPartyUInfo(Base64URL.encode("party-u"))
            .agreementPartyVInfo(Base64URL.encode("party-v"))
            .customParams(ContextAad.claims(URI, METHOD, Direction.REQUEST, TS, NONCE))
            .build();
        byte[] request = "apu/apv interop".getBytes(StandardCharsets.UTF_8);
        JWEObject jwe = new JWEObject(header, new Payload(request));
        jwe.encrypt(new ECDHEncrypter((ECPublicKey)server.getPublic()));

        JweContext context = codec.decryptRequest(jwe.serialize(), URI, METHOD);
        assertArrayEquals(request, context.plaintext());
    }

    @Test
    void 与非自家enc家族的交叉组合一律拒绝配对() {
        EcCipherSuite suite = new EcCipherSuite();
        assertTrue(suite.pairsWith("ECDH-ES", "A256GCM"));
        assertFalse(suite.pairsWith("ECDH-ES", "SM4-GCM"), "ECDH-ES 的 CEK 由 enc 派生，不能配 SM4-GCM");
        assertFalse(suite.pairsWith("RSA-OAEP-256", "A256GCM"));
    }

    // ---------------------------------------------------------------- 代码校验

    @Test
    void 公私钥不匹配时拒绝() {
        KeyPair a = p256Unchecked();
        KeyPair b = p256Unchecked();
        EncryptorException e = assertThrows(EncryptorException.class, () -> ServerKeyStore.builder()
            .add("ec-bad", b64(a.getPrivate().getEncoded()), b64(b.getPublic().getEncoded()), KeyType.EC)
            .build());
        assertTrue(e.getMessage().contains("不匹配"), e.getMessage());
    }

    @Test
    void 非P256曲线拒绝() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair p384 = generator.generateKeyPair();
        EncryptorException e = assertThrows(EncryptorException.class, () -> ServerKeyStore.builder()
            .add("ec-384", b64(p384.getPrivate().getEncoded()), b64(p384.getPublic().getEncoded()), KeyType.EC)
            .build());
        assertTrue(e.getMessage().contains("P-256"), e.getMessage());
    }

    @Test
    void JWKS与SPKI是P256形态() {
        ServerKeyStore keys = store("ec-1", p256Unchecked());
        assertEquals(KeyType.EC, keys.keyType("ec-1"));
        Map<String, Object> jwk = keys.jwk("ec-1");
        assertEquals("EC", jwk.get("kty"));
        assertEquals("P-256", jwk.get("crv"));
        assertEquals("ECDH-ES", jwk.get("alg"));
        assertNotNull(jwk.get("x"));
        assertNotNull(jwk.get("y"));
        assertNotNull(keys.spkiBase64("ec-1"));
        assertNotNull(keys.privateKey("ec-1"));
    }

    // ---------------------------------------------------------------- 反向：畸形报文

    @Test
    void encryptedKey段非空拒绝() throws Exception {
        KeyPair server = p256();
        JweCodec codec = codec(store("ec-1", server));
        String compact = oracle(server, "x".getBytes(StandardCharsets.UTF_8));
        String[] parts = compact.split("\\.", -1);
        parts[1] = Base64URL.encode(new byte[32]).toString();
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> codec.decryptRequest(String.join(".", parts), URI, METHOD));
        assertEquals(EncryptorFailure.BAD_HEADER, e.failure());
    }

    @Test
    void epk换到P384曲线拒绝() throws Exception {
        KeyPair server = p256();
        JweCodec codec = codec(store("ec-1", server));
        String compact = oracle(server, "x".getBytes(StandardCharsets.UTF_8));
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        ECPublicKey wrong = (ECPublicKey)generator.generateKeyPair().getPublic();
        Map<String, Object> epk = new LinkedHashMap<>();
        epk.put("kty", "EC");
        epk.put("crv", "P-384");
        epk.put("x", Base64URL.encode(fixed(wrong.getW().getAffineX(), 48)).toString());
        epk.put("y", Base64URL.encode(fixed(wrong.getW().getAffineY(), 48)).toString());
        Map<String, Object> header = headerOf(compact);
        header.put("epk", epk);
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> codec.decryptRequest(withHeader(compact, header), URI, METHOD));
        assertEquals(EncryptorFailure.ALG_NOT_ALLOWED, e.failure());
    }

    @Test
    void 缺少epk拒绝() throws Exception {
        KeyPair server = p256();
        JweCodec codec = codec(store("ec-1", server));
        String compact = oracle(server, "x".getBytes(StandardCharsets.UTF_8));
        Map<String, Object> header = headerOf(compact);
        header.remove("epk");
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> codec.decryptRequest(withHeader(compact, header), URI, METHOD));
        assertEquals(EncryptorFailure.BAD_HEADER, e.failure());
    }

    @Test
    void epk携带私钥参数拒绝() throws Exception {
        KeyPair server = p256();
        JweCodec codec = codec(store("ec-1", server));
        String compact = oracle(server, "x".getBytes(StandardCharsets.UTF_8));
        Map<String, Object> header = headerOf(compact);
        @SuppressWarnings("unchecked")
        Map<String, Object> epk = (Map<String, Object>)header.get("epk");
        epk.put("d", Base64URL.encode(new byte[32]).toString());
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> codec.decryptRequest(withHeader(compact, header), URI, METHOD));
        assertEquals(EncryptorFailure.BAD_HEADER, e.failure());
    }

    @Test
    void RSA密钥配ECDH_ES拒绝() throws Exception {
        ServerKeyStore keys = ServerKeyStore.builder()
            .add("rsa-1", Dummy.rsaPrivate(), Dummy.rsaPublic(), KeyType.RSA)
            .build();
        JweCodec codec = new JweCodec(keys, Collections.singletonList(new EcCipherSuite()),
            Collections.singleton("ECDH-ES"), Collections.singleton("A256GCM"));
        KeyPair ephemeral = p256();
        JWEObject jwe = new JWEObject(requestHeader("rsa-1"), new Payload("x".getBytes(StandardCharsets.UTF_8)));
        jwe.encrypt(new ECDHEncrypter((ECPublicKey)ephemeral.getPublic()));
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> codec.decryptRequest(jwe.serialize(), URI, METHOD));
        assertEquals(EncryptorFailure.ALG_NOT_ALLOWED, e.failure());
    }

    // ---------------------------------------------------------------- Concat KDF 定点

    @Test
    void concatKdf符合SP800_56A的OtherInfo排列() throws Exception {
        byte[] z = new byte[32];
        for (int i = 0; i < z.length; i++) {
            z[i] = (byte)i;
        }
        assertArrayEquals(expectedCek(z, "A256GCM", 256), ConcatKdf.derive(z, "A256GCM", 256));
        assertArrayEquals(expectedCek(z, "A128GCM", 128), ConcatKdf.derive(z, "A128GCM", 128));
        assertArrayEquals(expectedCek(z, "SM4-GCM", 128), ConcatKdf.derive(z, "SM4-GCM", 128));
        assertThrows(IllegalArgumentException.class, () -> ConcatKdf.derive(z, "A256GCM", 512));
    }

    private static byte[] expectedCek(byte[] z, String algorithmId, int keyLengthBits) throws Exception {
        byte[] algorithm = algorithmId.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream other = new ByteArrayOutputStream();
        writeInt(other, algorithm.length);
        other.write(algorithm);
        writeInt(other, 0);
        writeInt(other, 0);
        writeInt(other, keyLengthBits);
        ByteArrayOutputStream input = new ByteArrayOutputStream();
        writeInt(input, 1);
        input.write(z);
        input.write(other.toByteArray());
        byte[] full = MessageDigest.getInstance("SHA-256").digest(input.toByteArray());
        return Arrays.copyOf(full, keyLengthBits / 8);
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write(value >>> 24);
        out.write(value >>> 16);
        out.write(value >>> 8);
        out.write(value);
    }

    // ---------------------------------------------------------------- 工具

    private static JweCodec codec(ServerKeyStore keys) {
        return new JweCodec(keys, Collections.singletonList(new EcCipherSuite()),
            Collections.singleton("ECDH-ES"), Collections.singleton("A256GCM"));
    }

    private static ServerKeyStore store(String kid, KeyPair pair) {
        return ServerKeyStore.builder()
            .add(kid, b64(pair.getPrivate().getEncoded()), b64(pair.getPublic().getEncoded()), KeyType.EC)
            .build();
    }

    private static String oracle(KeyPair server, byte[] plaintext) throws Exception {
        JWEObject jwe = new JWEObject(requestHeader(), new Payload(plaintext));
        jwe.encrypt(new ECDHEncrypter((ECPublicKey)server.getPublic()));
        return jwe.serialize();
    }

    private static JWEHeader requestHeader() {
        return requestHeader("ec-1");
    }

    private static JWEHeader requestHeader(String kid) {
        return new JWEHeader.Builder(JWEAlgorithm.parse(EcCipherSuite.ALG), EncryptionMethod.A256GCM)
            .keyID(kid)
            .customParams(ContextAad.claims(URI, METHOD, Direction.REQUEST, TS, NONCE))
            .build();
    }

    private static Map<String, Object> headerOf(String compact) throws Exception {
        return new LinkedHashMap<>(JWEObject.parse(compact).getHeader().toJSONObject());
    }

    /**
     * 直接按 <b>原始 JSON</b> 重写 protected header 段——绕开 nimbus 的 header 构造期校验，
     * 用来模拟"攻击者手工拼的畸形 header"（真实报文本来就是字节，服务端只用 JSON 解析）。
     */
    private static String withHeader(String compact, Map<String, Object> header) throws Exception {
        String[] parts = compact.split("\\.", -1);
        String json = com.nimbusds.jose.util.JSONObjectUtils.toJSONString(header);
        StringBuilder builder = new StringBuilder(Base64URL.encode(json.getBytes(StandardCharsets.UTF_8)).toString());
        for (int i = 1; i < parts.length; i++) {
            builder.append('.').append(parts[i]);
        }
        return builder.toString();
    }

    private static KeyPair p256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static KeyPair p256Unchecked() {
        try {
            return p256();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] fixed(java.math.BigInteger value, int size) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[size];
        if (raw.length >= size) {
            System.arraycopy(raw, raw.length - size, out, 0, size);
        } else {
            System.arraycopy(raw, 0, out, size - raw.length, raw.length);
        }
        return out;
    }

    private static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /** 只为 RSA 密钥类型分支提供一对合法 RSA 密钥（用 JDK 生成，随机）。 */
    private static final class Dummy {
        private static final String[] RSA = rsaKeyPair();

        private static String rsaPrivate() {
            return RSA[0];
        }

        private static String rsaPublic() {
            return RSA[1];
        }

        private static String[] rsaKeyPair() {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                KeyPair pair = generator.generateKeyPair();
                return new String[] {b64(pair.getPrivate().getEncoded()), b64(pair.getPublic().getEncoded())};
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
