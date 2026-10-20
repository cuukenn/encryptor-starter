package io.github.cuukenn.encryptor.protocol;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.jose.KeyType;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link DefaultProtocol} 契约测试：默认协议栈的组装与 fail-fast 校验。
 *
 * @author changgg
 */
class DefaultProtocolTest {

    @Test
    void keys集合为null时给出明确错误() {
        EncryptorException error = assertThrows(EncryptorException.class,
            () -> DefaultProtocol.builder().keys(null));

        assertTrue(error.getMessage().contains("null"), "错误信息应说明 keys 不能为 null");
    }

    private static DefaultProtocol.KeyMaterial rsaKey(String kid) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return new DefaultProtocol.KeyMaterial(kid, KeyType.RSA,
            Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()),
            Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    }

    private static DefaultProtocol.KeyMaterial ecKey(String kid) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        return new DefaultProtocol.KeyMaterial(kid, KeyType.EC,
            Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()),
            Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    }

    @Test
    void EC密钥默认alg白名单含ECDHES() throws Exception {
        DefaultProtocol protocol = DefaultProtocol.builder().key(ecKey("ec1")).build();

        assertTrue(protocol.allowedAlgs().contains("ECDH-ES"), "有 EC 密钥时默认可接受 ECDH-ES");
        assertFalse(protocol.allowedAlgs().contains("RSA-OAEP-256"), "只有 EC 密钥时默认不接受 RSA");
        assertTrue(protocol.allowedEncs().contains("A256GCM"), "EC 密钥默认走 AES-GCM");
    }

    @Test
    void 组装出可用的默认栈() throws Exception {
        DefaultProtocol protocol = DefaultProtocol.builder()
            .key(rsaKey("k1"))
            .build();

        assertNotNull(protocol.keys());
        assertNotNull(protocol.codec());
        assertNotNull(protocol.replayGuard());
        assertNotNull(protocol.nonceChecker());
        assertNotNull(protocol.runtime());
        assertEquals("k1", protocol.keys().activeKid());
        assertFalse(protocol.runtime().bypassRequest());
        assertFalse(protocol.runtime().bypassResponse());
    }

    @Test
    void 空白名单默认跟密钥类型联动() throws Exception {
        DefaultProtocol rsaOnly = DefaultProtocol.builder().key(rsaKey("k1")).build();
        assertEquals(Collections.singleton("RSA-OAEP-256"), rsaOnly.allowedAlgs(),
            "只有 RSA 密钥时默认不接受 SM2");
        assertEquals(Collections.singleton("A256GCM"), rsaOnly.allowedEncs(), "RSA 默认只收 A256GCM");

    }

    @Test
    void 显式白名单覆盖默认() throws Exception {
        DefaultProtocol protocol = DefaultProtocol.builder()
            .key(rsaKey("k1"))
            .allowedAlgs(Collections.singleton("RSA-OAEP-256"))
            .allowedEncs(Collections.singleton("A128GCM"))
            .build();
        assertEquals(Collections.singleton("A128GCM"), protocol.allowedEncs());
    }

    @Test
    void 无密钥构造抛异常() {
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> DefaultProtocol.builder().build());
        assertTrue(e.getMessage().contains("密钥"), "错误信息应说明没有配置密钥: " + e.getMessage());
    }

    @Test
    void 未知activeKid构造抛异常() throws Exception {
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> DefaultProtocol.builder().key(rsaKey("k1")).activeKid("nope").build());
        assertTrue(e.getMessage().contains("nope"), "错误信息应点名未知 kid: " + e.getMessage());
    }

    @Test
    void ttl非法回退默认值() throws Exception {
        DefaultProtocol protocol = DefaultProtocol.builder()
            .key(rsaKey("k1"))
            .ttlMillis(0)
            .build();
        assertEquals(DefaultProtocol.DEFAULT_TTL_MILLIS, protocol.ttlMillis());

        DefaultProtocol explicit = DefaultProtocol.builder()
            .key(rsaKey("k1"))
            .ttlMillis(60_000L)
            .build();
        assertEquals(60_000L, explicit.ttlMillis());
    }

    @Test
    void nonce保留期短于时间窗时构造期失败() throws Exception {
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> DefaultProtocol.builder()
                .key(rsaKey("k1"))
                .ttlMillis(60_000L)
                .nonceRetentionMillis(30_000L)
                .build());
        assertTrue(e.getMessage().contains("nonce-retention"),
            "错误信息应点名 nonce-retention: " + e.getMessage());
    }

    @Test
    void 自定义NonceChecker时nonce保留期短于时间窗仍可构造() throws Exception {
        io.github.cuukenn.encryptor.jose.NonceChecker custom = nonce -> true;
        DefaultProtocol protocol = DefaultProtocol.builder()
            .key(rsaKey("k1"))
            .ttlMillis(60_000L)
            .nonceRetentionMillis(30_000L)
            .nonceChecker(custom)
            .build();

        assertSame(custom, protocol.nonceChecker(),
            "自定义 NonceChecker 不使用 nonce-retention，应允许短于 ttl");
    }

    @Test
    void nonce保留期等于时间窗时构造失败() throws Exception {
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> DefaultProtocol.builder()
                .key(rsaKey("k1"))
                .ttlMillis(60_000L)
                .nonceRetentionMillis(60_000L)
                .build());
        assertTrue(e.getMessage().contains("2*ttl"),
            "错误信息应说明需要覆盖未来时间戳: " + e.getMessage());
    }

    @Test
    void nonce保留期等于2倍时间窗时构造成功() throws Exception {
        DefaultProtocol protocol = DefaultProtocol.builder()
            .key(rsaKey("k1"))
            .ttlMillis(60_000L)
            .nonceRetentionMillis(120_000L)
            .build();

        assertNotNull(protocol.nonceChecker());
    }

    @Test
    void 只有RSA密钥时默认enc白名单不含SM4GCM() throws Exception {
        DefaultProtocol protocol = DefaultProtocol.builder().key(rsaKey("k1")).build();
        assertTrue(protocol.allowedEncs().contains("A256GCM"), "RSA 默认应接受 A256GCM");
        assertFalse(protocol.allowedEncs().contains("SM4-GCM"), "无 SM2 密钥时默认不应接受 SM4-GCM");
    }

    @Test
    void 可注入自定义NonceChecker() throws Exception {
        io.github.cuukenn.encryptor.jose.NonceChecker custom = nonce -> true;
        DefaultProtocol protocol = DefaultProtocol.builder()
            .key(rsaKey("k1"))
            .nonceChecker(custom)
            .build();
        assertSame(custom, protocol.nonceChecker());
    }

    @Test
    void SM2密钥在缺少encryptor_sm时启动期失败并给出提示() {
        // core 测试 classpath 没有 encryptor-sm；KeyMaterial 合法与否不重要：解析器缺失必须先生效
        DefaultProtocol.KeyMaterial material = new DefaultProtocol.KeyMaterial("sm2-1", KeyType.SM2, "AAAA", "BBBB");
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> DefaultProtocol.builder().key(material).build());
        assertTrue(e.getMessage().contains("encryptor-sm"),
            "错误信息必须提示显式添加 encryptor-sm 依赖: " + e.getMessage());
    }
}
