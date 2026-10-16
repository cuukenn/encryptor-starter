package io.github.cuukenn.encryptor.jose;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
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
}
