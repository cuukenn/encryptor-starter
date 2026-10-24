package io.github.cuukenn.encryptor.sm;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.jose.KeyEntry;
import io.github.cuukenn.encryptor.jose.KeyEntryParser;
import io.github.cuukenn.encryptor.jose.KeyType;
import io.github.cuukenn.encryptor.jose.PublicKeyInfo;
import io.github.cuukenn.encryptor.jose.ServerKeyStore;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECPoint;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64URL;

import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SM2 密钥解析器（{@link KeyEntryParser} SPI 的国密实现）。
 *
 * <p>从 core 迁出：私钥按 PKCS#8 配置，公钥按 SPKI（DER 的 base64）或<b>裸 64 字节 x||y</b>
 * （base64）配置；曲线必须是 {@code sm2p256v1}，公私钥必须配对 —— 都在构造期校验（fail-fast）。
 * 只使用 BouncyCastle 轻量级 API，<b>不注册全局 Provider</b>。</p>
 *
 * <p>通过 {@code META-INF/services/io.github.cuukenn.encryptor.jose.KeyEntryParser} 注册，
 * 由 {@link ServerKeyStore.Builder} 在启动期用 {@link java.util.ServiceLoader} 发现。</p>
 *
 * @author changgg
 */
public class SmKeyEntryParser implements KeyEntryParser {

    /** JWKS 里 SM2 公钥的曲线名（JWK 规范未注册，属于本项目约定的私有取值）。 */
    private static final String SM2_CRV = "SM2";

    private static final int SM2_POINT_PREFIX = 0x04;
    private static final int SM2_COORDINATE_BYTES = 32;
    private static final int SM2_RAW_PUBLIC_BYTES = SM2_COORDINATE_BYTES * 2;

    /** SM2 曲线域参数（用于显式曲线参数的等价性比对）。 */
    static final X9ECParameters SM2_DOMAIN = CustomNamedCurves.getByName("sm2p256v1");

    @Override
    public boolean supports(KeyType type) {
        return type == KeyType.SM2;
    }

    @Override
    public KeyEntry parse(String kid, String privateKeyBase64, String publicKeyBase64) {
        try {
            return sm2Entry(kid, privateKeyBase64, publicKeyBase64);
        } catch (EncryptorException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptorException("密钥 kid=" + kid + " 解析失败: " + e.getMessage(), e);
        }
    }

    private static KeyEntry sm2Entry(String kid, String privPkcs8Base64, String pubBase64) throws Exception {
        byte[] privDer = Base64.getDecoder().decode(privPkcs8Base64);
        byte[] pubBytes = Base64.getDecoder().decode(pubBase64);

        // 曲线必须是 SM2：命名曲线 OID 或与 sm2p256v1 等价的显式曲线参数（BC 自产 PKCS#8 是后者）
        PrivateKeyInfo privateInfo = PrivateKeyInfo.getInstance(privDer);
        if (!isSm2Algorithm(privateInfo.getPrivateKeyAlgorithm())) {
            throw new EncryptorException("密钥 kid=" + kid + " 的曲线不是 SM2");
        }
        AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(privDer);
        if (!(privateKey instanceof ECPrivateKeyParameters)) {
            throw new EncryptorException("密钥 kid=" + kid + " 不是 EC 私钥");
        }
        ECPrivateKeyParameters privateParams = (ECPrivateKeyParameters)privateKey;
        ECDomainParameters domain = privateParams.getParameters();

        // 公钥两种写法：SPKI(DER) 或裸 64 字节 x||y
        ECPoint configured;
        if (pubBytes.length == SM2_RAW_PUBLIC_BYTES) {
            byte[] pointBytes = new byte[SM2_RAW_PUBLIC_BYTES + 1];
            pointBytes[0] = (byte)SM2_POINT_PREFIX;
            System.arraycopy(pubBytes, 0, pointBytes, 1, SM2_RAW_PUBLIC_BYTES);
            configured = domain.getCurve().decodePoint(pointBytes);
        } else {
            AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(pubBytes);
            if (!(publicKey instanceof ECPublicKeyParameters)) {
                throw new EncryptorException("密钥 kid=" + kid + " 不是 EC 公钥");
            }
            ECPublicKeyParameters publicParams = (ECPublicKeyParameters)publicKey;
            // 显式比对公钥曲线与私钥域参数：不依赖 BC ECPoint.equals 的坐标值语义
            if (!publicParams.getParameters().getCurve().equals(domain.getCurve())
                || !publicParams.getParameters().getG().equals(domain.getG())
                || !publicParams.getParameters().getN().equals(domain.getN())) {
                throw new EncryptorException("密钥 kid=" + kid + " 的公钥曲线与私钥域参数不一致");
            }
            configured = publicParams.getQ();
        }
        // 用"从私钥推导公钥并逐点比对"取代曲线上点校验：等价且更强
        ECPoint derived = domain.getG().multiply(privateParams.getD()).normalize();
        if (!derived.equals(configured.normalize())) {
            throw new EncryptorException("密钥 kid=" + kid + " 的公私钥不匹配");
        }

        // SPKI：显式写死 id-ecPublicKey + sm2p256v1，避免依赖曲线名解析
        String spki = Base64.getEncoder().encodeToString(
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(new ECPublicKeyParameters(derived, domain))
                .getEncoded(ASN1Encoding.DER));
        PublicKeyInfo info = new PublicKeyInfo(kid, SmCipherSuite.ALG, spki, sm2Jwk(kid, derived), false);
        return new KeyEntry(kid, KeyType.SM2, null, null, info, privateKey);
    }

    /** 曲线是否 SM2：命名曲线 OID，或与 sm2p256v1 等价的显式曲线参数（BC 自产 PKCS#8 就是后者）。 */
    private static boolean isSm2Algorithm(AlgorithmIdentifier algorithmId) {
        ASN1ObjectIdentifier algorithm = algorithmId.getAlgorithm();
        if (GMObjectIdentifiers.sm2p256v1.equals(algorithm)) {
            return true;
        }
        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
            return false;
        }
        ASN1Encodable rawParams = algorithmId.getParameters();
        if (rawParams instanceof ASN1ObjectIdentifier) {
            return GMObjectIdentifiers.sm2p256v1.equals(rawParams);
        }
        if (rawParams == null || rawParams instanceof ASN1Null) {
            return false;
        }
        try {
            X962Parameters params = X962Parameters.getInstance(rawParams.toASN1Primitive());
            if (params.isNamedCurve()) {
                return GMObjectIdentifiers.sm2p256v1.equals(ASN1ObjectIdentifier.getInstance(params.getParameters()));
            }
            return isSm2Curve(X9ECParameters.getInstance(params.getParameters()));
        } catch (Exception e) {
            return false;
        }
    }

    /** 显式曲线参数与 sm2p256v1 是否等价（比对阶、生成元、a/b 与域大小，杜绝"同 n 同 G 的自造曲线"混入）。 */
    private static boolean isSm2Curve(X9ECParameters parsed) {
        X9ECParameters sm2 = SM2_DOMAIN;
        return parsed != null && sm2 != null && sm2.getN().equals(parsed.getN())
            && sm2.getG().equals(parsed.getG())
            // FieldElement 跨曲线实例的 equals 不可靠，用模数值比对
            && sm2.getCurve().getA().toBigInteger().equals(parsed.getCurve().getA().toBigInteger())
            && sm2.getCurve().getB().toBigInteger().equals(parsed.getCurve().getB().toBigInteger())
            && parsed.getCurve().getFieldSize() == SM2_COORDINATE_BYTES * 8;
    }

    private static Map<String, Object> sm2Jwk(String kid, ECPoint point) {
        byte[] encoded = point.getEncoded(false);
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", SM2_CRV);
        jwk.put("x", Base64URL.encode(Arrays.copyOfRange(encoded, 1, 1 + SM2_COORDINATE_BYTES)).toString());
        jwk.put("y", Base64URL.encode(Arrays.copyOfRange(encoded, 1 + SM2_COORDINATE_BYTES,
            1 + SM2_COORDINATE_BYTES * 2)).toString());
        jwk.put("kid", kid);
        jwk.put("alg", SmCipherSuite.ALG);
        jwk.put("use", KeyUse.ENCRYPTION.toString());
        return jwk;
    }
}
