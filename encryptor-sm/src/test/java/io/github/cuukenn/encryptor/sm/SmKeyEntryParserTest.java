package io.github.cuukenn.encryptor.sm;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.jose.KeyType;
import io.github.cuukenn.encryptor.jose.ServerKeyStore;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link SmKeyEntryParser} 契约测试（从 core 迁出，保证 core 测试零 BouncyCastle 依赖）。
 *
 * @author changgg
 */
class SmKeyEntryParserTest {

    /** 现场生成一对 EC 密钥（{@code curve} 例如 {@code sm2p256v1}、{@code P-256}）。 */
    private static AsymmetricCipherKeyPair newEcKeyPair(String curve) {
        X9ECParameters params = CustomNamedCurves.getByName(curve);
        ECDomainParameters domain = new ECDomainParameters(
            params.getCurve(), params.getG(), params.getN(), params.getH());
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(domain, new SecureRandom()));
        return generator.generateKeyPair();
    }

    private static String sm2Priv(AsymmetricCipherKeyPair pair) throws Exception {
        return Base64.getEncoder().encodeToString(
            PrivateKeyInfoFactory.createPrivateKeyInfo(pair.getPrivate())
                .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER));
    }

    private static String sm2PubSpki(AsymmetricCipherKeyPair pair) throws Exception {
        return Base64.getEncoder().encodeToString(
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pair.getPublic())
                .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER));
    }

    /** 未压缩点 04||x||y 去掉前缀 → 裸 64 字节 x||y（配置里允许的另一种公钥写法）。 */
    private static String sm2PubRaw64(AsymmetricCipherKeyPair pair) {
        byte[] encoded = ((ECPublicKeyParameters) pair.getPublic()).getQ().getEncoded(false);
        assertArrayEquals(new byte[] {0x04}, Arrays.copyOf(encoded, 1));
        return Base64.getEncoder().encodeToString(Arrays.copyOfRange(encoded, 1, 65));
    }

    @Test
    void 只声明支持SM2() {
        SmKeyEntryParser parser = new SmKeyEntryParser();
        assertTrue(parser.supports(KeyType.SM2));
        assertFalse(parser.supports(KeyType.RSA));
        assertFalse(parser.supports(KeyType.EC));
    }

    @Test
    void SM2密钥进JWKS带crvSM2且不含私钥() throws Exception {
        AsymmetricCipherKeyPair pair = newEcKeyPair("sm2p256v1");
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
        assertNotNull(store.nativePrivateKey("sm2-1"));
        assertNull(store.privateKey("sm2-1"), "SM2 条目不产出 JCE 私钥（不注册 BC Provider）");

        // SPKI 必须是可用的 SM2 公钥
        ECPublicKeyParameters spkiKey = (ECPublicKeyParameters)
            PublicKeyFactory.createKey(Base64.getDecoder().decode(store.spkiBase64("sm2-1")));
        byte[] spkiEncoded = spkiKey.getQ().getEncoded(false);
        byte[] expected = ((ECPublicKeyParameters) pair.getPublic()).getQ().getEncoded(false);
        assertArrayEquals(expected, spkiEncoded, "SPKI 必须与配置的 SM2 公钥是同一把");
        assertTrue(spkiIsSm2(store, "sm2-1"), "导出的 SPKI 必须仍标记为 SM2 曲线");
    }

    @Test
    void SM2用RSA密钥配置即抛异常() throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        java.security.KeyPair pair = generator.generateKeyPair();
        String priv = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
        String pub = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        assertThrows(EncryptorException.class,
            () -> ServerKeyStore.builder().add("bad", priv, pub, KeyType.SM2).build());
    }

    @Test
    void SM2用非SM2曲线的密钥构造即抛异常() throws Exception {
        AsymmetricCipherKeyPair p256 = newEcKeyPair("P-256");
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> ServerKeyStore.builder().add("wrong", sm2Priv(p256), sm2PubSpki(p256), KeyType.SM2).build());
        assertTrue(e.getMessage().contains("SM2"), "错误信息应说明不是 SM2 曲线: " + e.getMessage());
    }

    @Test
    void SM2公私钥不匹配时构造抛异常() throws Exception {
        AsymmetricCipherKeyPair a = newEcKeyPair("sm2p256v1");
        AsymmetricCipherKeyPair b = newEcKeyPair("sm2p256v1");
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> ServerKeyStore.builder().add("mix-sm2", sm2Priv(a), sm2PubSpki(b), KeyType.SM2).build());
        assertTrue(e.getMessage().contains("不匹配"), "错误信息应说明公私钥不匹配: " + e.getMessage());
    }

    @Test
    void SM2公钥可用裸64字节x_y配置并导出同一把SPKI与JWK() throws Exception {
        AsymmetricCipherKeyPair pair = newEcKeyPair("sm2p256v1");
        ServerKeyStore store = ServerKeyStore.builder()
            .add("sm2-raw", sm2Priv(pair), sm2PubRaw64(pair), KeyType.SM2)
            .build();

        Map<String, Object> jwk = store.jwk("sm2-raw");
        assertEquals("SM2", jwk.get("crv"));
        ECPublicKeyParameters rawFromSpki = (ECPublicKeyParameters)
            PublicKeyFactory.createKey(Base64.getDecoder().decode(store.spkiBase64("sm2-raw")));
        byte[] configured = ((ECPublicKeyParameters) pair.getPublic()).getQ()
            .normalize().getEncoded(false);
        assertArrayEquals(configured, rawFromSpki.getQ().normalize().getEncoded(false),
            "裸 64 字节公钥必须与 SPKI 编码表示同一把密钥");
    }

    /**
     * 导出的 SPKI 是否仍标记为 SM2 曲线：命名 OID、id-ecPublicKey+命名 OID、
     * 或显式参数（BC 自产密钥常见）三种编码都可能，与解析器的识别规则一致。
     */
    private static boolean spkiIsSm2(ServerKeyStore store, String kid) {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
            Base64.getDecoder().decode(store.spkiBase64(kid)));
        ASN1Encodable params = spki.getAlgorithm().getParameters();
        if (params instanceof ASN1ObjectIdentifier) {
            return GMObjectIdentifiers.sm2p256v1.equals(params);
        }
        X962Parameters x962 = X962Parameters.getInstance(params);
        if (x962.isNamedCurve()) {
            return GMObjectIdentifiers.sm2p256v1.equals(
                ASN1ObjectIdentifier.getInstance(x962.getParameters()));
        }
        X9ECParameters parsed = X9ECParameters.getInstance(x962.getParameters());
        return SmKeyEntryParser.SM2_DOMAIN.getN().equals(parsed.getN())
            && SmKeyEntryParser.SM2_DOMAIN.getG().equals(parsed.getG());
    }
}
