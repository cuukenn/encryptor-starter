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

    private static DefaultProtocol.KeyMaterial rsaKey(String kid) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return new DefaultProtocol.KeyMaterial(kid, KeyType.RSA,
            Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()),
            Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    }

    private static DefaultProtocol.KeyMaterial sm2Key(String kid) throws Exception {
        org.bouncycastle.asn1.x9.X9ECParameters params =
            org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("sm2p256v1");
        org.bouncycastle.crypto.params.ECDomainParameters domain =
            new org.bouncycastle.crypto.params.ECDomainParameters(params.getCurve(), params.getG(),
                params.getN(), params.getH());
        org.bouncycastle.crypto.generators.ECKeyPairGenerator generator =
            new org.bouncycastle.crypto.generators.ECKeyPairGenerator();
        generator.init(new org.bouncycastle.crypto.params.ECKeyGenerationParameters(domain,
            new java.security.SecureRandom()));
        org.bouncycastle.crypto.AsymmetricCipherKeyPair pair = generator.generateKeyPair();

        byte[] privPkcs8 = org.bouncycastle.crypto.util.PrivateKeyInfoFactory
            .createPrivateKeyInfo(((org.bouncycastle.crypto.params.ECPrivateKeyParameters) pair.getPrivate()))
            .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
        byte[] pubSpki = org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
            .createSubjectPublicKeyInfo(((org.bouncycastle.crypto.params.ECPublicKeyParameters) pair.getPublic()))
            .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
        return new DefaultProtocol.KeyMaterial(kid, KeyType.SM2,
            Base64.getEncoder().encodeToString(privPkcs8),
            Base64.getEncoder().encodeToString(pubSpki));
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

        DefaultProtocol mixed = DefaultProtocol.builder()
            .key(rsaKey("k1"))
            .key(sm2Key("k2"))
            .build();
        assertTrue(mixed.allowedAlgs().contains("SM2"), "混钥时默认应接受 SM2");
        assertTrue(mixed.allowedAlgs().contains("RSA-OAEP-256"));
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
    void 只有RSA密钥时默认enc白名单不含SM4GCM() throws Exception {
        DefaultProtocol protocol = DefaultProtocol.builder().key(rsaKey("k1")).build();
        assertTrue(protocol.allowedEncs().contains("A256GCM"), "RSA 默认应接受 A256GCM");
        assertFalse(protocol.allowedEncs().contains("SM4-GCM"), "无 SM2 密钥时默认不应接受 SM4-GCM");
    }

    @Test
    void SM2密钥默认enc白名单联动含SM4GCM() throws Exception {
        DefaultProtocol protocol = DefaultProtocol.builder().key(sm2Key("k1")).build();
        assertTrue(protocol.allowedEncs().contains("SM4-GCM"), "有 SM2 密钥时默认可接受 SM4-GCM");
    }

    @Test
    void 混钥默认enc白名单含两套() throws Exception {
        DefaultProtocol protocol = DefaultProtocol.builder().key(rsaKey("k1")).key(sm2Key("k2")).build();
        assertTrue(protocol.allowedEncs().contains("A256GCM"));
        assertTrue(protocol.allowedEncs().contains("SM4-GCM"));
    }

    @Test
    void SM2密钥但显式enc白名单缺SM4GCM时构造期失败() throws Exception {
        EncryptorException e = assertThrows(EncryptorException.class, () -> DefaultProtocol.builder()
            .key(sm2Key("k1"))
            .allowedEncs(Collections.singleton("A256GCM"))
            .build());
        assertTrue(e.getMessage().contains("SM4-GCM"), "错误信息应点明缺失的 enc: " + e.getMessage());
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
}
