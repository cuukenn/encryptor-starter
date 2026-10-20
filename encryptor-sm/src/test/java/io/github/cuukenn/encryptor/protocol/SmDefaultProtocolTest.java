package io.github.cuukenn.encryptor.protocol;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.jose.Direction;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.jose.KeyType;
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
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SM2 相关默认协议栈用例（从 core 迁出）。
 *
 * <p>这些用例同时是 <b>ServiceLoader 接线守卫</b>：{@code encryptor-sm} 在
 * {@code META-INF/services} 里注册了 {@code KeyEntryParser} 与 {@code CipherSuite}，
 * 所以只写 {@code KeyType.SM2} 就能完成"解析密钥 + 装配套件 + 解密请求"整条链路。</p>
 *
 * @author changgg
 */
class SmDefaultProtocolTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int CEK_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 16;

    private static AsymmetricCipherKeyPair sm2KeyPair() {
        org.bouncycastle.asn1.x9.X9ECParameters params = CustomNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(),
            params.getN(), params.getH());
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(domain, RANDOM));
        return generator.generateKeyPair();
    }

    private static DefaultProtocol.KeyMaterial sm2Key(String kid) throws Exception {
        AsymmetricCipherKeyPair pair = sm2KeyPair();
        byte[] privPkcs8 = PrivateKeyInfoFactory.createPrivateKeyInfo(
            (ECPrivateKeyParameters) pair.getPrivate()).getEncoded(ASN1Encoding.DER);
        byte[] pubSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
            (ECPublicKeyParameters) pair.getPublic()).getEncoded(ASN1Encoding.DER);
        return new DefaultProtocol.KeyMaterial(kid, KeyType.SM2,
            Base64.getEncoder().encodeToString(privPkcs8),
            Base64.getEncoder().encodeToString(pubSpki));
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
    void EC与SM2并存时enc白名单同时含AES与SM4GCM() throws Exception {
        DefaultProtocol protocol = DefaultProtocol.builder().key(ecKey("ec1")).key(sm2Key("sm1")).build();

        assertTrue(protocol.allowedEncs().contains("A256GCM"), "有 EC 密钥时默认可接受 A256GCM");
        assertTrue(protocol.allowedEncs().contains("SM4-GCM"), "有 SM2 密钥时默认可接受 SM4-GCM");
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

    /**
     * 端到端守卫：只用 {@code KeyType.SM2} 配置，解析器与套件都必须由 ServiceLoader 自动接上。
     */
    @Test
    void ServiceLoader自动发现配置器与套件并解密SM2请求() throws Exception {
        AsymmetricCipherKeyPair pair = sm2KeyPair();
        String priv = Base64.getEncoder().encodeToString(PrivateKeyInfoFactory
            .createPrivateKeyInfo((ECPrivateKeyParameters) pair.getPrivate()).getEncoded(ASN1Encoding.DER));
        String pub = Base64.getEncoder().encodeToString(SubjectPublicKeyInfoFactory
            .createSubjectPublicKeyInfo((ECPublicKeyParameters) pair.getPublic()).getEncoded(ASN1Encoding.DER));

        DefaultProtocol protocol = DefaultProtocol.builder()
            .key(new DefaultProtocol.KeyMaterial("sm1", KeyType.SM2, priv, pub))
            .build();

        assertEquals(Collections.singleton("SM2"), protocol.allowedAlgs(), "SM2 密钥默认只接受 SM2 封装");
        assertTrue(protocol.allowedEncs().contains("SM4-GCM"));

        String uri = "/api/sm";
        String method = "POST";
        byte[] plaintext = "国密端到端（ServiceLoader 接线）".getBytes(StandardCharsets.UTF_8);
        String compact = seal((ECPublicKeyParameters) pair.getPublic(), plaintext, uri, method);

        JweContext context = protocol.codec().decryptRequest(compact, uri, method);
        assertArrayEquals(plaintext, context.plaintext());
        assertEquals("SM2", context.alg());
        assertEquals("SM4-GCM", context.enc());
        assertEquals("sm1", context.kid());
    }

    /** 客户端视角：SM2(C1C3C2) 封 CEK + SM4-GCM 加密正文，手拼 compact（AAD = protected header 的 base64url 文本）。 */
    private static String seal(ECPublicKeyParameters publicKey, byte[] plaintext, String uri, String method)
        throws Exception {
        byte[] cek = new byte[CEK_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(cek);
        RANDOM.nextBytes(iv);

        String header = "{\"alg\":\"SM2\",\"enc\":\"SM4-GCM\",\"kid\":\"sm1\",\"typ\":\"encryptor+jwe\""
            + ",\"uri\":\"" + uri + "\",\"m\":\"" + method + "\",\"dir\":\"" + Direction.REQUEST.code()
            + "\",\"ts\":" + System.currentTimeMillis() + ",\"nonce\":\"" + UUID.randomUUID() + "\"}";
        byte[] headerBytes = header.getBytes(StandardCharsets.US_ASCII);
        String headerSegment = b64u(headerBytes, 0, headerBytes.length);
        byte[] aad = headerSegment.getBytes(StandardCharsets.US_ASCII);

        SM2Engine sm2 = new SM2Engine(SM2Engine.Mode.C1C3C2);
        sm2.init(true, new ParametersWithRandom(publicKey, RANDOM));
        byte[] wrapped = sm2.processBlock(cek, 0, cek.length);

        GCMBlockCipher gcm = new GCMBlockCipher(new SM4Engine());
        gcm.init(true, new AEADParameters(new KeyParameter(cek), TAG_LENGTH * 8, iv, aad));
        byte[] cipherTextTag = new byte[gcm.getOutputSize(plaintext.length)];
        int length = gcm.processBytes(plaintext, 0, plaintext.length, cipherTextTag, 0);
        gcm.doFinal(cipherTextTag, length);

        return headerSegment + "." + b64u(wrapped, 0, wrapped.length) + "."
            + b64u(iv, 0, iv.length) + "."
            + b64u(cipherTextTag, 0, cipherTextTag.length - TAG_LENGTH) + "."
            + b64u(cipherTextTag, cipherTextTag.length - TAG_LENGTH, TAG_LENGTH);
    }

    private static String b64u(byte[] bytes, int offset, int length) {
        byte[] slice = new byte[length];
        System.arraycopy(bytes, offset, slice, 0, length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(slice);
    }
}
