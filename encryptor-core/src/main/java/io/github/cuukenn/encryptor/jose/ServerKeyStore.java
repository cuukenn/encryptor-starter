package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.KeyAgreement;

/**
 * 服务端密钥库：多 {@code kid} 并存（支持轮换），按 {@code kid} 取私钥、导出只含公钥的 JWK 与 SPKI。
 *
 * <p>构建后完全不可变 —— 线程安全由不可变性保证，内部不持有任何共享可变状态
 * （尤其不缓存 {@code Cipher}：{@code Cipher} 非线程安全，缓存单实例会把 RSA 运算全局串行化）。
 *
 * <p>支持两种密钥类型（{@link KeyType}）：
 * <ul>
 *   <li>{@link KeyType#RSA}：JCE 可直接用，{@link #privateKey} / {@link #publicKey} 返回 JCE 密钥。</li>
 *   <li>{@link KeyType#SM2}：走 BouncyCastle 轻量级 API，<b>不注册全局 Provider</b>，
 *       因此 {@link #privateKey} / {@link #publicKey} 对 SM2 条目返回 {@code null}，
 *       请用 {@link #sm2PrivateKey} 取 {@link AsymmetricKeyParameter}。</li>
 * </ul>
 *
 * <p>SM2 私钥按 PKCS#8 配置，公钥按 SPKI（DER 的 base64）或<b>裸 64 字节 x||y</b>（base64）配置；
 * 曲线必须是 {@code sm2p256v1}，公私钥必须配对 —— 都在构造期校验（fail-fast）。
 *
 * @author changgg
 */
public final class ServerKeyStore {

    /** JWKS 里 SM2 公钥的曲线名（JWK 规范未注册，属于本项目约定的私有取值）。 */
    private static final String SM2_CRV = "SM2";

    private static final int SM2_POINT_PREFIX = 0x04;
    private static final int SM2_COORDINATE_BYTES = 32;
    private static final int SM2_RAW_PUBLIC_BYTES = SM2_COORDINATE_BYTES * 2;

    /** SM2 标准曲线参数（用于显式曲线参数的等价性比对）。 */
    /** SM2 曲线域参数（包内可见，供测试断言 SPKI 仍标记为 SM2）。 */
    static final org.bouncycastle.asn1.x9.X9ECParameters SM2_DOMAIN =
        org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("sm2p256v1");

    private final Map<String, Entry> entries;
    private final List<PublicKeyInfo> publicKeys;
    private final String activeKid;

    private ServerKeyStore(Map<String, Entry> entries, String activeKid) {
        this.entries = Collections.unmodifiableMap(entries);
        this.activeKid = activeKid;
        List<PublicKeyInfo> keys = new ArrayList<>(entries.size());
        for (Entry entry : entries.values()) {
            keys.add(entry.publicKeyInfo);
        }
        this.publicKeys = Collections.unmodifiableList(keys);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * 单密钥便捷构造（RSA）。
     *
     * @param kid             密钥标识
     * @param privPkcs8Base64 私钥（PKCS#8 DER 的 base64）
     * @param pubX509Base64   公钥（X.509 SubjectPublicKeyInfo 的 base64）
     * @param active          是否设为当前推荐 kid
     */
    public static ServerKeyStore fromBase64(String kid, String privPkcs8Base64, String pubX509Base64, boolean active) {
        Builder builder = builder().add(kid, privPkcs8Base64, pubX509Base64, KeyType.RSA);
        if (active) {
            builder.activeKid(kid);
        }
        return builder.build();
    }

    public boolean contains(String kid) {
        return entries.containsKey(kid);
    }

    /** 密钥类型；未知 kid 返回 {@code null}。 */
    public KeyType keyType(String kid) {
        Entry entry = entries.get(kid);
        return entry == null ? null : entry.type;
    }

    /** 未知 kid 或非 RSA 条目返回 {@code null}（SM2 条目请用 {@link #sm2PrivateKey}）。 */
    public PrivateKey privateKey(String kid) {
        Entry entry = entries.get(kid);
        return entry == null ? null : entry.privateKey;
    }

    /** 未知 kid 或非 RSA 条目返回 {@code null}。 */
    public PublicKey publicKey(String kid) {
        Entry entry = entries.get(kid);
        return entry == null ? null : entry.publicKey;
    }

    /** 供 JWE 解码器使用的 nimbus 密钥（含私钥）；未知 kid 或非 RSA 条目返回 {@code null}。 */
    public RSAKey rsaKey(String kid) {
        Entry entry = entries.get(kid);
        return entry == null ? null : entry.rsaKey;
    }

    /** SM2 私钥参数（BC 轻量级 API）；未知 kid 或非 SM2 条目返回 {@code null}。 */
    public AsymmetricKeyParameter sm2PrivateKey(String kid) {
        Entry entry = entries.get(kid);
        return entry == null ? null : entry.sm2PrivateKey;
    }

    public String activeKid() {
        return activeKid;
    }

    /** X.509 SubjectPublicKeyInfo 的 base64（不含 PEM 头尾）；未知 kid 返回 {@code null}。 */
    public String spkiBase64(String kid) {
        Entry entry = entries.get(kid);
        return entry == null ? null : entry.publicKeyInfo.spkiBase64();
    }

    /** 只含公钥的标准 JWK；未知 kid 返回 {@code null}。 */
    public Map<String, Object> jwk(String kid) {
        Entry entry = entries.get(kid);
        return entry == null ? null : entry.publicKeyInfo.jwk();
    }

    public List<PublicKeyInfo> publicKeys() {
        return publicKeys;
    }

    private static final class Entry {
        private final KeyType type;
        private final PrivateKey privateKey;
        private final PublicKey publicKey;
        private final RSAKey rsaKey;
        private final AsymmetricKeyParameter sm2PrivateKey;
        private final PublicKeyInfo publicKeyInfo;

        private Entry(KeyType type, PrivateKey privateKey, PublicKey publicKey, RSAKey rsaKey,
                      AsymmetricKeyParameter sm2PrivateKey, PublicKeyInfo publicKeyInfo) {
            this.type = type;
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.rsaKey = rsaKey;
            this.sm2PrivateKey = sm2PrivateKey;
            this.publicKeyInfo = publicKeyInfo;
        }
    }

    public static final class Builder {
        private final Map<String, Entry> entries = new LinkedHashMap<>();
        private String activeKid;

        /** 添加一把 RSA 密钥；解析失败立刻抛出（fail-fast，不等第一个请求）。 */
        public Builder add(String kid, String privPkcs8Base64, String pubX509Base64) {
            return add(kid, privPkcs8Base64, pubX509Base64, KeyType.RSA);
        }

        /**
         * 添加一把指定类型的密钥；解析失败立刻抛出（fail-fast，不等第一个请求）。
         *
         * @param type {@link KeyType#RSA}（JCE 解析）或 {@link KeyType#SM2}（BC 解析、校验曲线与配对）
         */
        public Builder add(String kid, String privPkcs8Base64, String pubBase64, KeyType type) {
            if (kid == null || kid.isEmpty()) {
                throw new EncryptorException("密钥 kid 不能为空");
            }
            if (entries.containsKey(kid)) {
                throw new EncryptorException("密钥 kid 重复: " + kid);
            }
            KeyType effectiveType = type == null ? KeyType.RSA : type;
            try {
                if (effectiveType == KeyType.SM2) {
                    entries.put(kid, sm2Entry(kid, privPkcs8Base64, pubBase64));
                } else if (effectiveType == KeyType.EC) {
                    entries.put(kid, ecEntry(kid, privPkcs8Base64, pubBase64));
                } else {
                    entries.put(kid, rsaEntry(kid, privPkcs8Base64, pubBase64));
                }
            } catch (EncryptorException e) {
                throw e;
            } catch (Exception e) {
                throw new EncryptorException("密钥 kid=" + kid + " 解析失败: " + e.getMessage(), e);
            }
            return this;
        }

        private Entry rsaEntry(String kid, String privPkcs8Base64, String pubX509Base64) throws Exception {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privPkcs8Base64)));
            PublicKey publicKey = keyFactory.generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(pubX509Base64)));
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            if (!rsaPrivateKey.getModulus().equals(rsaPublicKey.getModulus())) {
                throw new EncryptorException("密钥 kid=" + kid + " 的公私钥不匹配");
            }
            RSAKey rsaKey = new RSAKey.Builder(
                Base64URL.encode(rsaPublicKey.getModulus()),
                Base64URL.encode(rsaPublicKey.getPublicExponent()))
                .privateKey(rsaPrivateKey)
                .keyID(kid)
                .algorithm(JWEAlgorithm.RSA_OAEP_256)
                .keyUse(KeyUse.ENCRYPTION)
                .build();
            PublicKeyInfo info = new PublicKeyInfo(kid, JWEAlgorithm.RSA_OAEP_256.getName(),
                Base64.getEncoder().encodeToString(publicKey.getEncoded()),
                rsaKey.toPublicJWK().toJSONObject(), false);
            return new Entry(KeyType.RSA, privateKey, publicKey, rsaKey, null, info);
        }

        /**
         * P-256 密钥（{@code ECDH-ES}）：私钥 PKCS#8、公钥 SPKI，两条都必须落在 secp256r1 上。
         */
        private Entry ecEntry(String kid, String privPkcs8Base64, String pubX509Base64) throws Exception {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privPkcs8Base64)));
            PublicKey publicKey = keyFactory.generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(pubX509Base64)));
            if (!(privateKey instanceof ECPrivateKey) || !(publicKey instanceof ECPublicKey)) {
                throw new EncryptorException("密钥 kid=" + kid + " 不是 EC 密钥");
            }
            ECPrivateKey ecPrivateKey = (ECPrivateKey)privateKey;
            ECPublicKey ecPublicKey = (ECPublicKey)publicKey;
            requireP256(kid, ecPrivateKey.getParams(), ecPublicKey.getParams());
            if (!matches(ecPublicKey, ecPrivateKey)) {
                throw new EncryptorException("密钥 kid=" + kid + " 的公私钥不匹配");
            }
            ECKey ecKey = new ECKey.Builder(Curve.P_256,
                coordinate(ecPublicKey.getW().getAffineX()), coordinate(ecPublicKey.getW().getAffineY()))
                .keyID(kid).algorithm(JWEAlgorithm.parse(EcCipherSuite.ALG)).keyUse(KeyUse.ENCRYPTION).build();
            PublicKeyInfo info = new PublicKeyInfo(kid, EcCipherSuite.ALG,
                Base64.getEncoder().encodeToString(publicKey.getEncoded()), ecKey.toPublicJWK().toJSONObject(), false);
            return new Entry(KeyType.EC, privateKey, publicKey, null, null, info);
        }

        private Entry sm2Entry(String kid, String privPkcs8Base64, String pubBase64) throws Exception {
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
            ECPrivateKeyParameters privateParams = (ECPrivateKeyParameters) privateKey;
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
                configured = ((ECPublicKeyParameters) publicKey).getQ();
            }
            // 用"从私钥推导公钥并逐点比对"取代曲线上点校验：等价且更强
            ECPoint derived = domain.getG().multiply(privateParams.getD()).normalize();            if (!derived.equals(configured.normalize())) {
                throw new EncryptorException("密钥 kid=" + kid + " 的公私钥不匹配");
            }

            // SPKI：显式写死 id-ecPublicKey + sm2p256v1，避免依赖曲线名解析
            String spki = Base64.getEncoder().encodeToString(
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(new ECPublicKeyParameters(derived, domain))
                    .getEncoded(ASN1Encoding.DER));
            PublicKeyInfo info = new PublicKeyInfo(kid, SmCipherSuite.ALG, spki, sm2Jwk(kid, derived), false);
            return new Entry(KeyType.SM2, null, null, null, privateKey, info);
        }

        /** 曲线是否 SM2：命名曲线 OID，或与 sm2p256v1 等价的显式曲线参数（BC 自产 PKCS#8 就是后者）。 */
        private static boolean isSm2Algorithm(org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithmId) {
            ASN1ObjectIdentifier algorithm = algorithmId.getAlgorithm();
            if (GMObjectIdentifiers.sm2p256v1.equals(algorithm)) {
                return true;
            }
            if (!org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
                return false;
            }
            org.bouncycastle.asn1.ASN1Encodable rawParams = algorithmId.getParameters();
            if (rawParams instanceof ASN1ObjectIdentifier) {
                return GMObjectIdentifiers.sm2p256v1.equals(rawParams);
            }
            if (rawParams == null || rawParams instanceof org.bouncycastle.asn1.ASN1Null) {
                return false;
            }
            try {
                org.bouncycastle.asn1.x9.X962Parameters params =
                    org.bouncycastle.asn1.x9.X962Parameters.getInstance(rawParams.toASN1Primitive());
                if (params.isNamedCurve()) {
                    return GMObjectIdentifiers.sm2p256v1.equals(
                        ASN1ObjectIdentifier.getInstance(params.getParameters()));
                }
                return isSm2Curve(org.bouncycastle.asn1.x9.X9ECParameters.getInstance(params.getParameters()));
            } catch (Exception e) {
                return false;
            }
        }

        /** 显式曲线参数与 sm2p256v1 是否等价（比对阶、生成元与域大小）。 */
        private static boolean isSm2Curve(org.bouncycastle.asn1.x9.X9ECParameters parsed) {
            org.bouncycastle.asn1.x9.X9ECParameters sm2 = SM2_DOMAIN;
            return parsed != null && sm2 != null && sm2.getN().equals(parsed.getN())
                && sm2.getG().equals(parsed.getG())
                && parsed.getCurve().getFieldSize() == SM2_COORDINATE_BYTES * 8;
        }

        /** 两条密钥的曲线参数都必须等于 P-256（secp256r1），否则拒绝（防降级到 P-384/P-521）。 */
        private static void requireP256(String kid, ECParameterSpec privParams, ECParameterSpec pubParams)
            throws Exception {
            ECParameterSpec p256 = p256Params();
            if (!p256.equals(privParams) || !p256.equals(pubParams)) {
                throw new EncryptorException("密钥 kid=" + kid + " 的曲线不是 P-256（secp256r1）");
            }
        }

        private static ECParameterSpec p256Params() throws Exception {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            return parameters.getParameterSpec(ECParameterSpec.class);
        }

        /**
         * 公私钥是否成对：一次"自协商"验证——临时密钥对分别与配置公钥、配置私钥协商，
         * 两次共享密钥相等 ⇔ 两条密钥同属一对。比"从私钥推公钥逐点比对"更直接，且只用 JCE。
         */
        private static boolean matches(ECPublicKey publicKey, ECPrivateKey privateKey) throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            java.security.KeyPair probe = generator.generateKeyPair();
            return MessageDigest.isEqual(agree(probe.getPrivate(), publicKey), agree(privateKey, probe.getPublic()));
        }

        private static byte[] agree(PrivateKey mine, PublicKey theirs) throws Exception {
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(mine);
            agreement.doPhase(theirs, true);
            return agreement.generateSecret();
        }

        /** 大整数坐标 → 定长 32 字节大端 Base64URL（JWK 的 x/y）。 */
        private static Base64URL coordinate(BigInteger value) {
            byte[] raw = value.toByteArray();
            byte[] fixed = new byte[32];
            if (raw.length >= 32) {
                System.arraycopy(raw, raw.length - 32, fixed, 0, 32);
            } else {
                System.arraycopy(raw, 0, fixed, 32 - raw.length, raw.length);
            }
            return Base64URL.encode(fixed);
        }

        private static Map<String, Object> sm2Jwk(String kid, ECPoint point) {            byte[] encoded = point.getEncoded(false);
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

        /** 当前推荐客户端使用的 kid；可为 null（不校验存在性由 {@link #build()} 兜底）。 */
        public Builder activeKid(String kid) {
            this.activeKid = kid;
            return this;
        }

        public ServerKeyStore build() {
            if (entries.isEmpty()) {
                throw new EncryptorException("至少需要配置一把密钥");
            }
            if (activeKid != null && !entries.containsKey(activeKid)) {
                throw new EncryptorException("active-kid 不在已配置的 kid 中: " + activeKid);
            }
            Map<String, Entry> finalEntries = new LinkedHashMap<>(entries.size());
            for (Map.Entry<String, Entry> item : entries.entrySet()) {
                Entry entry = item.getValue();
                boolean active = item.getKey().equals(activeKid);
                PublicKeyInfo old = entry.publicKeyInfo;
                PublicKeyInfo current = active == old.active() ? old
                    : new PublicKeyInfo(old.kid(), old.alg(), old.spkiBase64(), old.jwk(), active);
                finalEntries.put(item.getKey(),
                    new Entry(entry.type, entry.privateKey, entry.publicKey, entry.rsaKey,
                        entry.sm2PrivateKey, current));
            }
            return new ServerKeyStore(finalEntries, activeKid);
        }
    }
}
