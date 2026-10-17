package io.github.cuukenn.encryptor.jose;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link ServerKeyStore} 契约测试。
 *
 * @author changgg
 */
class ServerKeyStoreTest {

    /** 现场生成一对 RSA 密钥，返回 [PKCS8 私钥 base64, X509 公钥 base64]。 */
    private static String[] newKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return new String[] {
            Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()),
            Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
        };
    }

    private static ServerKeyStore store(boolean active) throws Exception {
        String[] key = newKeyPair();
        return ServerKeyStore.builder().add("k1", key[0], key[1]).activeKid(active ? "k1" : null).build();
    }

    @Test
    void 按kid取私钥_未知kid返回null() throws Exception {
        String[] k1 = newKeyPair();
        String[] k2 = newKeyPair();
        ServerKeyStore store = ServerKeyStore.builder()
            .add("k1", k1[0], k1[1])
            .add("k2", k2[0], k2[1])
            .activeKid("k2")
            .build();

        assertTrue(store.contains("k1"));
        assertTrue(store.contains("k2"));
        assertFalse(store.contains("missing"));
        assertNull(store.privateKey("missing"));
        assertEquals("k2", store.activeKid());
        assertEquals(2, store.publicKeys().size());
        // 私钥确实是各自那一把（比较编码字节，不依赖 Key 实现的 equals）
        assertArrayEquals(Base64.getDecoder().decode(k1[0]), store.privateKey("k1").getEncoded());
    }

    @Test
    void jwk只含公钥字段() throws Exception {
        ServerKeyStore store = store(true);
        Map<String, Object> jwk = store.jwk("k1");

        assertEquals("RSA", jwk.get("kty"));
        assertEquals("RSA-OAEP-256", jwk.get("alg"));
        assertEquals("enc", jwk.get("use"));
        assertEquals("k1", jwk.get("kid"));
        assertNotNull(jwk.get("n"));
        assertNotNull(jwk.get("e"));
        assertFalse(jwk.containsKey("d"), "JWK 不得包含私钥指数 d");
        assertFalse(jwk.containsKey("p"));
        assertFalse(jwk.containsKey("q"));
    }

    @Test
    void spki可被jdk重新导入并可做oaep加密() throws Exception {
        ServerKeyStore store = store(true);
        String spki = store.spkiBase64("k1");

        PublicKey publicKey = KeyFactory.getInstance("RSA")
            .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(spki)));
        // nimbus 之外也能用：JCE 侧做一次 OAEP-SHA256 加密（这里只验证密钥可用）
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal("hello".getBytes("UTF-8"));
        assertNotNull(encrypted);
        assertTrue(encrypted.length > 0);

        // 公钥描述里也必须带 SPKI
        List<PublicKeyInfo> keys = store.publicKeys();
        assertEquals("k1", keys.get(0).kid());
        assertEquals(spki, keys.get(0).spkiBase64());
        assertTrue(keys.get(0).active());
    }

    @Test
    void 非法密钥构造即抛出异常() {
        assertThrows(EncryptorException.class,
            () -> ServerKeyStore.builder().add("bad", "not-a-base64-key", "also-bad").activeKid("bad").build());
    }

    @Test
    void activeKid必须在已添加的kid中() throws Exception {
        String[] k1 = newKeyPair();
        ServerKeyStore.Builder builder = ServerKeyStore.builder().add("k1", k1[0], k1[1]);
        assertThrows(EncryptorException.class, () -> builder.activeKid("nope").build());
    }

    @Test
    void publicKeys返回不可修改的列表() throws Exception {
        ServerKeyStore store = store(true);
        List<PublicKeyInfo> keys = store.publicKeys();
        assertThrows(UnsupportedOperationException.class, () -> keys.add(null));
    }

    @Test
    void 公私钥不匹配时构造抛异常() throws Exception {
        String[] k1 = newKeyPair();
        String[] k2 = newKeyPair();
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> ServerKeyStore.builder().add("mix", k1[0], k2[1]).build());
        assertTrue(e.getMessage().contains("不匹配"), "错误信息应说明公私钥不匹配: " + e.getMessage());
    }

    // ---------------------------------------------------------------- SM2（国密）

    /** 现场生成一对 EC 密钥（{@code curve} 例如 {@code sm2p256v1}、{@code P-256}）。 */
    private static org.bouncycastle.crypto.AsymmetricCipherKeyPair newEcKeyPair(String curve) {
        org.bouncycastle.asn1.x9.X9ECParameters params =
            org.bouncycastle.crypto.ec.CustomNamedCurves.getByName(curve);
        org.bouncycastle.crypto.params.ECDomainParameters domain = new org.bouncycastle.crypto.params.ECDomainParameters(
            params.getCurve(), params.getG(), params.getN(), params.getH());
        org.bouncycastle.crypto.generators.ECKeyPairGenerator generator =
            new org.bouncycastle.crypto.generators.ECKeyPairGenerator();
        generator.init(new org.bouncycastle.crypto.params.ECKeyGenerationParameters(domain,
            new java.security.SecureRandom()));
        return generator.generateKeyPair();
    }

    private static String sm2Priv(org.bouncycastle.crypto.AsymmetricCipherKeyPair pair) throws Exception {
        return Base64.getEncoder().encodeToString(
            org.bouncycastle.crypto.util.PrivateKeyInfoFactory.createPrivateKeyInfo(pair.getPrivate())
                .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER));
    }

    private static String sm2PubSpki(org.bouncycastle.crypto.AsymmetricCipherKeyPair pair) throws Exception {
        return Base64.getEncoder().encodeToString(
            org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pair.getPublic())
                .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER));
    }

    /** 未压缩点 04||x||y 去掉前缀 → 裸 64 字节 x||y（配置里允许的另一种公钥写法）。 */
    private static String sm2PubRaw64(org.bouncycastle.crypto.AsymmetricCipherKeyPair pair) {
        byte[] encoded = ((org.bouncycastle.crypto.params.ECPublicKeyParameters) pair.getPublic()).getQ()
            .getEncoded(false);
        assertArrayEquals(new byte[] {0x04}, Arrays.copyOf(encoded, 1));
        return Base64.getEncoder().encodeToString(Arrays.copyOfRange(encoded, 1, 65));
    }

    @Test
    void SM2密钥进JWKS带crvSM2且不含私钥() throws Exception {
        org.bouncycastle.crypto.AsymmetricCipherKeyPair pair = newEcKeyPair("sm2p256v1");
        ServerKeyStore store = ServerKeyStore.builder()
            .add("sm2-1", sm2Priv(pair), sm2PubSpki(pair), KeyType.SM2)
            .activeKid("sm2-1")
            .build();

        Map<String, Object> jwk = store.jwk("sm2-1");
        assertEquals("EC", jwk.get("kty"));
        assertEquals("SM2", jwk.get("crv"), "JWKS 必须声明国密曲线");
        assertEquals("SM2", jwk.get("alg"));
        assertEquals("enc", jwk.get("use"));
        assertEquals("sm2-1", jwk.get("kid"));
        assertNotNull(jwk.get("x"));
        assertNotNull(jwk.get("y"));
        assertFalse(jwk.containsKey("d"), "JWK 不得包含私钥");
        assertFalse(jwk.containsKey("k"));

        assertEquals(KeyType.SM2, store.keyType("sm2-1"));
        assertNull(store.keyType("rsa-none"), "未知 kid 返回 null");
        assertNull(store.keyType("missing"));
        assertNotNull(store.sm2PrivateKey("sm2-1"));
        assertNull(store.privateKey("sm2-1"), "SM2 条目不产出 JCE 私钥（不注册 BC Provider）");

        // SPKI 必须是可用的 SM2 公钥
        org.bouncycastle.crypto.params.ECPublicKeyParameters spkiKey =
            (org.bouncycastle.crypto.params.ECPublicKeyParameters)
                org.bouncycastle.crypto.util.PublicKeyFactory.createKey(
                    Base64.getDecoder().decode(store.spkiBase64("sm2-1")));
        byte[] spkiEncoded = spkiKey.getQ().getEncoded(false);
        byte[] expected = ((org.bouncycastle.crypto.params.ECPublicKeyParameters) pair.getPublic()).getQ()
            .getEncoded(false);
        assertArrayEquals(expected, spkiEncoded, "SPKI 必须与配置的 SM2 公钥是同一把");
        assertTrue(spkiIsSm2(store, "sm2-1"), "导出的 SPKI 必须仍标记为 SM2 曲线");
    }

    @Test
    void SM2用RSA密钥配置即抛异常() throws Exception {
        String[] rsa = newKeyPair();
        assertThrows(EncryptorException.class,
            () -> ServerKeyStore.builder().add("bad", rsa[0], rsa[1], KeyType.SM2).build());
    }

    @Test
    void SM2用非SM2曲线的密钥构造即抛异常() throws Exception {
        org.bouncycastle.crypto.AsymmetricCipherKeyPair p256 = newEcKeyPair("P-256");
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> ServerKeyStore.builder().add("wrong", sm2Priv(p256), sm2PubSpki(p256), KeyType.SM2).build());
        assertTrue(e.getMessage().contains("SM2"), "错误信息应说明不是 SM2 曲线: " + e.getMessage());
    }

    @Test
    void SM2公私钥不匹配时构造抛异常() throws Exception {
        org.bouncycastle.crypto.AsymmetricCipherKeyPair a = newEcKeyPair("sm2p256v1");
        org.bouncycastle.crypto.AsymmetricCipherKeyPair b = newEcKeyPair("sm2p256v1");
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> ServerKeyStore.builder().add("mix-sm2", sm2Priv(a), sm2PubSpki(b), KeyType.SM2).build());
        assertTrue(e.getMessage().contains("不匹配"), "错误信息应说明公私钥不匹配: " + e.getMessage());
    }

    @Test
    void SM2公钥可用裸64字节x_y配置并导出同一把SPKI与JWK() throws Exception {
        org.bouncycastle.crypto.AsymmetricCipherKeyPair pair = newEcKeyPair("sm2p256v1");
        ServerKeyStore store = ServerKeyStore.builder()
            .add("sm2-raw", sm2Priv(pair), sm2PubRaw64(pair), KeyType.SM2)
            .build();

        Map<String, Object> jwk = store.jwk("sm2-raw");
        assertEquals("SM2", jwk.get("crv"));
        org.bouncycastle.crypto.params.ECPublicKeyParameters rawFromSpki =
            (org.bouncycastle.crypto.params.ECPublicKeyParameters)
                org.bouncycastle.crypto.util.PublicKeyFactory.createKey(
                    Base64.getDecoder().decode(store.spkiBase64("sm2-raw")));
        byte[] configured = ((org.bouncycastle.crypto.params.ECPublicKeyParameters) pair.getPublic()).getQ()
            .normalize().getEncoded(false);
        assertArrayEquals(configured, rawFromSpki.getQ().normalize().getEncoded(false),
            "裸 64 字节公钥必须与 SPKI 编码表示同一把密钥");
    }

    /**
     * 导出的 SPKI 是否仍标记为 SM2 曲线：命名 OID、id-ecPublicKey+命名 OID、
     * 或显式参数（BC 自产密钥常见）三种编码都可能，与 ServerKeyStore 的识别规则一致。
     */
    private static boolean spkiIsSm2(ServerKeyStore store, String kid) {
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(
                Base64.getDecoder().decode(store.spkiBase64(kid)));
        org.bouncycastle.asn1.ASN1Encodable params = spki.getAlgorithm().getParameters();
        if (params instanceof org.bouncycastle.asn1.ASN1ObjectIdentifier) {
            return org.bouncycastle.asn1.gm.GMObjectIdentifiers.sm2p256v1
                .equals(params);
        }
        org.bouncycastle.asn1.x9.X962Parameters x962 =
            org.bouncycastle.asn1.x9.X962Parameters.getInstance(params);
        if (x962.isNamedCurve()) {
            return org.bouncycastle.asn1.gm.GMObjectIdentifiers.sm2p256v1.equals(
                org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance(x962.getParameters()));
        }
        org.bouncycastle.asn1.x9.X9ECParameters parsed =
            org.bouncycastle.asn1.x9.X9ECParameters.getInstance(x962.getParameters());
        return ServerKeyStore.SM2_DOMAIN.getN().equals(parsed.getN())
            && ServerKeyStore.SM2_DOMAIN.getG().equals(parsed.getG());
    }
}
