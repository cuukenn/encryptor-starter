package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link JweCodec} 请求方向解密契约测试。
 *
 * <p>客户端侧一律用 nimbus 现成 API 自建 JWE（8.4 节：示例前端也按同一规则生成 compact）。
 *
 * @author changgg
 */
class JweCodecTest {

    private static final String KID = "k1";
    private static final String URI = "/pay/x";

    private static KeyPair keyPair;
    private static ServerKeyStore store;
    private static JweCodec codec;

    @BeforeAll
    static void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        store = ServerKeyStore.builder()
            .add(KID, base64(keyPair.getPrivate().getEncoded()), base64(keyPair.getPublic().getEncoded()))
            .activeKid(KID)
            .build();
        codec = new JweCodec(store, Collections.emptySet(), Collections.emptySet());
    }

    @Test
    void 解密客户端构造的请求() throws Exception {
        long ts = System.currentTimeMillis();
        String compact = clientJwe("hello".getBytes(StandardCharsets.UTF_8), URI, "post", ts, "n1",
            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, KID);

        JweContext context = codec.decryptRequest(compact, URI, "POST");

        assertEquals("hello", new String(context.plaintext(), StandardCharsets.UTF_8));
        assertEquals(32, context.cek().length, "A256GCM 的 CEK 必须是 32 字节");
        assertEquals(KID, context.kid());
        assertEquals("RSA-OAEP-256", context.alg());
        assertEquals("A256GCM", context.enc());
        assertEquals(ts, context.ts());
        assertEquals("n1", context.nonce());
    }

    @Test
    void 篡改任一字节都必须失败() throws Exception {
        String compact = clientJwe("hello".getBytes(StandardCharsets.UTF_8), URI, "POST",
            System.currentTimeMillis(), "n1", JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, KID);
        String[] parts = compact.split("\\.");

        for (int i = 0; i < parts.length; i++) {
            String mutated = mutateFirstChar(parts, i);
            EncryptorException e = assertThrows(EncryptorException.class,
                () -> codec.decryptRequest(mutated, URI, "POST"), "第 " + i + " 段被篡改却通过了");
            assertNotNull(e.failure(), "失败必须带分类");
        }
    }

    @Test
    void 算法或加密方法不在白名单一律拒绝() throws Exception {
        long ts = System.currentTimeMillis();
        String rsa15 = clientJwe("hi".getBytes(StandardCharsets.UTF_8), URI, "POST", ts, "n1",
            JWEAlgorithm.RSA1_5, EncryptionMethod.A256GCM, KID);
        assertEquals(EncryptorFailure.ALG_NOT_ALLOWED,
            assertThrows(EncryptorException.class, () -> codec.decryptRequest(rsa15, URI, "POST")).failure());

        String a256 = clientJwe("hi".getBytes(StandardCharsets.UTF_8), URI, "POST", ts, "n1",
            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, KID);
        JweCodec onlyA128 = new JweCodec(store, Collections.emptySet(), Collections.singleton("A128GCM"));
        assertEquals(EncryptorFailure.ENC_NOT_ALLOWED,
            assertThrows(EncryptorException.class, () -> onlyA128.decryptRequest(a256, URI, "POST")).failure());
    }

    @Test
    void 构造期拒绝未实现的算法() {
        assertThrows(EncryptorException.class,
            () -> new JweCodec(store, Collections.singleton("RSA-OAEP"), Collections.emptySet()),
            "配置了未实现的 alg 必须在构造期 fail-fast");
        assertThrows(EncryptorException.class,
            () -> new JweCodec(store, Collections.emptySet(), Collections.singleton("A128CBC-HS256")),
            "配置了未实现的 enc 必须在构造期 fail-fast");
    }

    @Test
    void 未知或缺省kid一律拒绝() throws Exception {
        long ts = System.currentTimeMillis();
        String unknown = clientJwe("hi".getBytes(StandardCharsets.UTF_8), URI, "POST", ts, "n1",
            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, "nope");
        assertEquals(EncryptorFailure.UNKNOWN_KID,
            assertThrows(EncryptorException.class, () -> codec.decryptRequest(unknown, URI, "POST")).failure());

        String noKid = clientJwe("hi".getBytes(StandardCharsets.UTF_8), URI, "POST", ts, "n1",
            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, null);
        assertEquals(EncryptorFailure.UNKNOWN_KID,
            assertThrows(EncryptorException.class, () -> codec.decryptRequest(noKid, URI, "POST")).failure());
    }

    @Test
    void 上下文不匹配一律拒绝() throws Exception {
        long ts = System.currentTimeMillis();
        String compact = clientJwe("hi".getBytes(StandardCharsets.UTF_8), URI, "POST", ts, "n1",
            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, KID);

        assertEquals(EncryptorFailure.AAD_MISMATCH,
            assertThrows(EncryptorException.class, () -> codec.decryptRequest(compact, "/other", "POST")).failure(),
            "换 uri 必须失败");
        assertEquals(EncryptorFailure.AAD_MISMATCH,
            assertThrows(EncryptorException.class, () -> codec.decryptRequest(compact, URI, "GET")).failure(),
            "换 method 必须失败");
    }

    @Test
    void 缺报文与非JWE报文一律拒绝() throws Exception {
        assertEquals(EncryptorFailure.MISSING,
            assertThrows(EncryptorException.class, () -> codec.decryptRequest(null, URI, "GET")).failure());
        assertEquals(EncryptorFailure.MISSING,
            assertThrows(EncryptorException.class, () -> codec.decryptRequest("  ", URI, "GET")).failure());
        assertEquals(EncryptorFailure.BAD_HEADER,
            assertThrows(EncryptorException.class, () -> codec.decryptRequest("not-a-jwe", URI, "GET")).failure());
        assertEquals(EncryptorFailure.BAD_HEADER,
            assertThrows(EncryptorException.class, () -> codec.decryptRequest("a.b.c.d.e", URI, "GET")).failure());
    }

    @Test
    void 缺ts或nonce一律拒绝() throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put(ContextAad.CLAIM_URI, URI);
        claims.put(ContextAad.CLAIM_METHOD, "POST");
        claims.put(ContextAad.CLAIM_DIRECTION, Direction.REQUEST.code());
        JWEObject jwe = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
            .keyID(KID).customParams(claims).build(), new Payload("hi"));
        jwe.encrypt(new RSAEncrypter((RSAPublicKey)keyPair.getPublic()));

        assertEquals(EncryptorFailure.BAD_HEADER,
            assertThrows(EncryptorException.class, () -> codec.decryptRequest(jwe.serialize(), URI, "POST")).failure(),
            "缺 ts/nonce 必须拒绝");
    }

    @Test
    void 响应可被同一CEK解回并绑定res方向() throws Exception {
        long ts = System.currentTimeMillis();
        String compact = clientJwe("req".getBytes(StandardCharsets.UTF_8), URI, "POST", ts, "n1",
            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, KID);
        JweContext context = codec.decryptRequest(compact, URI, "POST");

        long resTs = System.currentTimeMillis();
        byte[] body = "world".getBytes(StandardCharsets.UTF_8);
        String response = codec.encryptResponse(body, context.cek(), URI, "POST", resTs, "n2");

        String[] parts = response.split("\\.");
        assertEquals(5, parts.length, "必须是 JWE compact");
        assertEquals("", parts[1], "alg=dir 的 encrypted_key（第 2 段）必须为空");

        JWEObject parsed = JWEObject.parse(response);
        assertEquals(JWEAlgorithm.DIR, parsed.getHeader().getAlgorithm());
        assertEquals(EncryptionMethod.A256GCM, parsed.getHeader().getEncryptionMethod());
        assertEquals(Direction.RESPONSE.code(), parsed.getHeader().getCustomParam(ContextAad.CLAIM_DIRECTION));
        assertEquals(resTs, ((Number)parsed.getHeader().getCustomParam(ContextAad.CLAIM_TS)).longValue());
        assertEquals("n2", parsed.getHeader().getCustomParam(ContextAad.CLAIM_NONCE));

        // 响应绑定的是响应方向：拿请求方向去校验必须失败
        EncryptorException mismatch = assertThrows(EncryptorException.class,
            () -> ContextAad.verify(parsed.getHeader().toJSONObject(), URI, "POST", Direction.REQUEST));
        assertTrue(mismatch.getMessage().contains("AAD"), mismatch.getMessage());

        parsed.decrypt(new DirectDecrypter(new SecretKeySpec(context.cek(), "AES")));
        assertArrayEquals(body, parsed.getPayload().toBytes(), "同一 CEK 必须能解回响应原文");
    }

    @Test
    void 每次响应使用新的IV() {
        byte[] cek = new byte[32];
        new java.security.SecureRandom().nextBytes(cek);
        String first = codec.encryptResponse("same".getBytes(StandardCharsets.UTF_8), cek, URI, "POST", 1L, "n1");
        String second = codec.encryptResponse("same".getBytes(StandardCharsets.UTF_8), cek, URI, "POST", 1L, "n2");
        assertNotEquals(first.split("\\.")[2], second.split("\\.")[2], "IV 必须每次新生成");
    }

    @Test
    void 非法长度的CEK拒绝() {
        assertEquals(EncryptorFailure.ENCRYPT_FAILED, assertThrows(EncryptorException.class,
            () -> codec.encryptResponse("x".getBytes(StandardCharsets.UTF_8), new byte[20], URI, "POST", 1L, "n1")).failure());
        assertEquals(EncryptorFailure.ENCRYPT_FAILED, assertThrows(EncryptorException.class,
            () -> codec.encryptResponse("x".getBytes(StandardCharsets.UTF_8), null, URI, "POST", 1L, "n1")).failure(),
            "CEK 缺失必须拒绝");
    }

    @Test
    void 按套件分派而非硬编码() throws Exception {
        // 允许 TEST-ALG/TEST-ENC 的只有"假套件"，能构造出来并解出内容即证明分派来自套件
        JweCodec fake = new JweCodec(store, Collections.singletonList(new FakeSuite()),
            Collections.singleton("TEST-ALG"), Collections.singleton("TEST-ENC"));
        String compact = fakeJwe("hi".getBytes(StandardCharsets.UTF_8), URI, "POST", 1L, "n1");

        JweContext context = fake.decryptRequest(compact, URI, "POST");

        assertEquals("hi", new String(context.plaintext(), StandardCharsets.UTF_8));
        assertEquals("TEST-ALG", context.alg());
        assertEquals("TEST-ENC", context.enc());
        assertEquals(4, context.cek().length, "CEK 长度必须取自套件");
    }

    @Test
    void 白名单来自已装配套件() {
        // 只有 JCE 套件时，TEST-ALG/TEST-ENC 必须在构造期被拒（不硬编码、也不放行未知算法）
        assertThrows(EncryptorException.class,
            () -> new JweCodec(store, Collections.singleton("TEST-ALG"), Collections.singleton("TEST-ENC")));
        // 空白名单 = 协议默认（RSA-OAEP-256/A256GCM）：套件不支持默认值时同样 fail-fast
        assertThrows(EncryptorException.class,
            () -> new JweCodec(store, Collections.singletonList(new FakeSuite()),
                Collections.emptySet(), Collections.emptySet()));
    }

    @Test
    void 响应可用显式enc封装() throws Exception {
        byte[] cek = new byte[4];
        new java.security.SecureRandom().nextBytes(cek);
        JweCodec fake = new JweCodec(store, Collections.singletonList(new FakeSuite()),
            Collections.singleton("TEST-ALG"), Collections.singleton("TEST-ENC"));

        String response = fake.encryptResponse("world".getBytes(StandardCharsets.UTF_8), cek, "TEST-ENC",
            URI, "POST", 2L, "n2");

        String[] parts = response.split("\\.");
        assertEquals(5, parts.length, "必须是 JWE compact");
        assertEquals("", parts[1], "alg=dir 的 encrypted_key 必须为空");
        JWEHeader header = JWEHeader.parse(new com.nimbusds.jose.util.Base64URL(parts[0]));
        assertEquals(JWEAlgorithm.DIR, header.getAlgorithm());
        assertEquals("TEST-ENC", header.getEncryptionMethod().getName());
        assertEquals(Direction.RESPONSE.code(), header.getCustomParam(ContextAad.CLAIM_DIRECTION));
        // 用假套件解回原文（tag 由套件自定义）
        byte[] packed = b64urlDecode(parts[3] + "." + parts[4]);
        assertArrayEquals("world".getBytes(StandardCharsets.UTF_8), new FakeSuite().aeadDecrypt("TEST-ENC", cek,
            new byte[12], java.util.Arrays.copyOf(packed, packed.length - 1),
            java.util.Arrays.copyOfRange(packed, packed.length - 1, packed.length), parts[0].getBytes("US-ASCII")));
    }

    @Test
    void 响应enc不被套件支持时拒绝() {
        assertEquals(EncryptorFailure.ENCRYPT_FAILED, assertThrows(EncryptorException.class,
            () -> codec.encryptResponse("x".getBytes(StandardCharsets.UTF_8), new byte[32], "A128CBC-HS256",
                URI, "POST", 1L, "n1")).failure());
    }

    /** 假套件：alg=TEST-ALG / enc=TEST-ENC（CEK 4 字节、xor 加密、tag = CEK 首字节）。用于证明分派来自套件而非硬编码。 */
    static final class FakeSuite implements CipherSuite {

        @Override
        public java.util.Set<String> algorithms() {
            return Collections.singleton("TEST-ALG");
        }

        @Override
        public java.util.Set<String> encryptionMethods() {
            return Collections.singleton("TEST-ENC");
        }

        @Override
        public byte[] unwrapCek(ServerKeyStore keys, String kid, String alg, byte[] encryptedKey) {
            return encryptedKey;
        }

        @Override
        public byte[] aeadEncrypt(String enc, byte[] cek, byte[] iv, byte[] plaintext, byte[] aad) {
            byte[] out = new byte[plaintext.length + 1];
            for (int i = 0; i < plaintext.length; i++) {
                out[i] = (byte)(plaintext[i] ^ cek[i % cek.length]);
            }
            out[plaintext.length] = cek[0];
            return out;
        }

        @Override
        public byte[] aeadDecrypt(String enc, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag, byte[] aad) {
            if (authTag.length != 1 || authTag[0] != cek[0]) {
                throw new IllegalStateException("tag 不匹配");
            }
            byte[] out = new byte[cipherText.length];
            for (int i = 0; i < cipherText.length; i++) {
                out[i] = (byte)(cipherText[i] ^ cek[i % cek.length]);
            }
            return out;
        }

        @Override
        public int keyLength(String enc) {
            return 4;
        }

        @Override
        public int tagLength(String enc) {
            return 1;
        }
    }

    private static String fakeJwe(byte[] plaintext, String uri, String method, long ts, String nonce) throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.parse("TEST-ALG"), EncryptionMethod.parse("TEST-ENC"))
            .keyID(KID)
            .customParams(ContextAad.claims(uri, method, Direction.REQUEST, ts, nonce))
            .build();
        String protectedHeader = header.toBase64URL().toString();
        byte[] cek = "cek1".getBytes(StandardCharsets.UTF_8);
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        byte[] packed = new FakeSuite().aeadEncrypt("TEST-ENC", cek, iv, plaintext,
            protectedHeader.getBytes(StandardCharsets.US_ASCII));
        return protectedHeader + "." + b64url(cek) + "." + b64url(iv) + "."
            + b64url(java.util.Arrays.copyOf(packed, packed.length - 1)) + "." + b64url(
            java.util.Arrays.copyOfRange(packed, packed.length - 1, packed.length));
    }

    private static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] b64urlDecode(String parts) {
        int index = parts.indexOf('.');
        byte[] cipherText = Base64.getUrlDecoder().decode(parts.substring(0, index));
        byte[] authTag = Base64.getUrlDecoder().decode(parts.substring(index + 1));
        byte[] packed = java.util.Arrays.copyOf(cipherText, cipherText.length + authTag.length);
        System.arraycopy(authTag, 0, packed, cipherText.length, authTag.length);
        return packed;
    }

    private static String clientJwe(byte[] plaintext, String uri, String method, long ts, String nonce,
                                    JWEAlgorithm alg, EncryptionMethod enc, String kid) throws Exception {
        JWEHeader.Builder builder = new JWEHeader.Builder(alg, enc)
            .customParams(ContextAad.claims(uri, method, Direction.REQUEST, ts, nonce));
        if (kid != null) {
            builder.keyID(kid);
        }
        JWEObject jwe = new JWEObject(builder.build(), new Payload(plaintext));
        jwe.encrypt(new RSAEncrypter((RSAPublicKey)keyPair.getPublic()));
        return jwe.serialize();
    }

    private static String mutateFirstChar(String[] parts, int index) {
        String[] copy = parts.clone();
        char first = copy[index].charAt(0);
        copy[index] = (first == 'A' ? 'B' : 'A') + copy[index].substring(1);
        return String.join(".", copy);
    }

    private static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
