package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import io.github.cuukenn.encryptor.exception.EncryptorException;

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
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

import javax.crypto.KeyAgreement;

/**
 * 服务端密钥库：多 {@code kid} 并存（支持轮换），按 {@code kid} 取私钥、导出只含公钥的 JWK 与 SPKI。
 *
 * <p>构建后完全不可变 —— 线程安全由不可变性保证，内部不持有任何共享可变状态
 * （尤其不缓存 {@code Cipher}：{@code Cipher} 非线程安全，缓存单实例会把 RSA 运算全局串行化）。
 *
 * <p>内置两种密钥类型（{@link KeyType}）：
 * <ul>
 *   <li>{@link KeyType#RSA}：JCE 可直接用，{@link #privateKey} / {@link #publicKey} 返回 JCE 密钥。</li>
 *   <li>{@link KeyType#EC}：P-256（{@code secp256r1}），JCE/SunEC 原生支持，用于 ECDH-ES。</li>
 * </ul>
 *
 * <p>其他类型通过 {@link KeyEntryParser} SPI + {@link ServiceLoader} 扩展。例如国密 SM2 由独立的
 * {@code encryptor-sm} 模块提供：核心模块<b>不依赖 BouncyCastle</b>，也未配置 SM2 解析器时，
 * 启动期会直接失败并提示添加 {@code encryptor-sm} 依赖（而不是等到第一个请求）。SM2 条目的
 * JCE 私钥/公钥为 {@code null}，第三方库句柄通过 {@link #nativePrivateKey(String)} 取得。</p>
 *
 * @author changgg
 */
public final class ServerKeyStore {

    private final Map<String, KeyEntry> entries;
    private final List<PublicKeyInfo> publicKeys;
    private final String activeKid;

    private ServerKeyStore(Map<String, KeyEntry> entries, String activeKid) {
        this.entries = Collections.unmodifiableMap(entries);
        this.activeKid = activeKid;
        List<PublicKeyInfo> keys = new ArrayList<>(entries.size());
        for (KeyEntry entry : entries.values()) {
            keys.add(entry.publicKeyInfo());
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
        KeyEntry entry = entries.get(kid);
        return entry == null ? null : entry.type();
    }

    /** 未知 kid 或非 JCE 条目（例如 SM2）返回 {@code null}。 */
    public PrivateKey privateKey(String kid) {
        KeyEntry entry = entries.get(kid);
        return entry == null ? null : entry.privateKey();
    }

    /** 未知 kid 或非 JCE 条目返回 {@code null}。 */
    public PublicKey publicKey(String kid) {
        KeyEntry entry = entries.get(kid);
        return entry == null ? null : entry.publicKey();
    }

    /**
     * 第三方库私钥句柄（不透明对象）；未知 kid 或该条目没有扩展私钥时返回 {@code null}。
     *
     * <p>SM2 套件（{@code encryptor-sm}）会把它强转成自己的 BouncyCastle 类型；
     * core 只负责透传，避免泄露任何第三方类型。</p>
     */
    public Object nativePrivateKey(String kid) {
        KeyEntry entry = entries.get(kid);
        return entry == null ? null : entry.nativePrivateKey();
    }

    /** 供 JWE 解码器使用的 nimbus 密钥（含私钥）；未知 kid 或非 RSA 条目返回 {@code null}。 */
    public RSAKey rsaKey(String kid) {
        KeyEntry entry = entries.get(kid);
        if (entry == null || entry.type() != KeyType.RSA) {
            return null;
        }
        RSAPrivateKey privateKey = (RSAPrivateKey)entry.privateKey();
        RSAPublicKey publicKey = (RSAPublicKey)entry.publicKey();
        return new RSAKey.Builder(
            Base64URL.encode(publicKey.getModulus()),
            Base64URL.encode(publicKey.getPublicExponent()))
            .privateKey(privateKey)
            .keyID(kid)
            .algorithm(JWEAlgorithm.RSA_OAEP_256)
            .keyUse(KeyUse.ENCRYPTION)
            .build();
    }

    public String activeKid() {
        return activeKid;
    }

    /** X.509 SubjectPublicKeyInfo 的 base64（不含 PEM 头尾）；未知 kid 返回 {@code null}。 */
    public String spkiBase64(String kid) {
        KeyEntry entry = entries.get(kid);
        return entry == null ? null : entry.publicKeyInfo().spkiBase64();
    }

    /** 只含公钥的标准 JWK；未知 kid 返回 {@code null}。 */
    public Map<String, Object> jwk(String kid) {
        KeyEntry entry = entries.get(kid);
        return entry == null ? null : entry.publicKeyInfo().jwk();
    }

    public List<PublicKeyInfo> publicKeys() {
        return publicKeys;
    }

    public static final class Builder {
        private final Map<String, KeyEntry> entries = new LinkedHashMap<>();
        private String activeKid;

        /** 添加一把 RSA 密钥；解析失败立刻抛出（fail-fast，不等第一个请求）。 */
        public Builder add(String kid, String privPkcs8Base64, String pubX509Base64) {
            return add(kid, privPkcs8Base64, pubX509Base64, KeyType.RSA);
        }

        /**
         * 添加一把指定类型的密钥；解析失败立刻抛出（fail-fast，不等第一个请求）。
         *
         * <p>RSA/EC 由 core 内置解析；其他类型（例如 {@link KeyType#SM2}）通过
         * {@link KeyEntryParser} 的 {@link ServiceLoader} 发现。若没有模块提供对应解析器，
         * 会直接抛出 {@link EncryptorException} 并提示添加 {@code encryptor-sm}。</p>
         *
         * @param type {@link KeyType#RSA}、{@link KeyType#EC}，或由扩展模块支持的类型
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
                if (effectiveType == KeyType.RSA) {
                    entries.put(kid, rsaEntry(kid, privPkcs8Base64, pubBase64));
                } else if (effectiveType == KeyType.EC) {
                    entries.put(kid, ecEntry(kid, privPkcs8Base64, pubBase64));
                } else {
                    entries.put(kid, optionalEntry(kid, privPkcs8Base64, pubBase64, effectiveType));
                }
            } catch (EncryptorException e) {
                throw e;
            } catch (Exception e) {
                throw new EncryptorException("密钥 kid=" + kid + " 解析失败: " + e.getMessage(), e);
            }
            return this;
        }

        /**
         * 通过 {@link ServiceLoader} 找可选类型的解析器。
         *
         * <p>没有解析器时抛出带可操作提示的异常：用户需要显式添加 {@code encryptor-sm} 依赖，
         * 而不是笼统地说"密钥解析失败"。</p>
         */
        private static KeyEntry optionalEntry(String kid, String privPkcs8Base64, String pubBase64, KeyType type) {
            for (KeyEntryParser parser : parsers()) {
                if (parser.supports(type)) {
                    return parser.parse(kid, privPkcs8Base64, pubBase64);
                }
            }
            throw new EncryptorException("密钥 kid=" + kid + " 的类型 " + type
                + " 需要额外的密钥解析模块：请显式添加 encryptor-sm 依赖"
                + "（io.github.cuukenn:encryptor-sm）；当前 classpath 没有支持该类型的 KeyEntryParser");
        }

        /** 加载全部 {@link KeyEntryParser}（启动期一次，失败直接暴露配置/打包问题）。 */
        private static List<KeyEntryParser> parsers() {
            List<KeyEntryParser> parsers = new ArrayList<>();
            try {
                for (KeyEntryParser parser : ServiceLoader.load(KeyEntryParser.class)) {
                    parsers.add(parser);
                }
            } catch (ServiceConfigurationError e) {
                throw new EncryptorException("加载 KeyEntryParser 失败: " + e.getMessage(), e);
            }
            return parsers;
        }

        private KeyEntry rsaEntry(String kid, String privPkcs8Base64, String pubX509Base64) throws Exception {
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
            int modulusBits = rsaPublicKey.getModulus().bitLength();
            if (modulusBits < 2048) {
                throw new EncryptorException("密钥 kid=" + kid + " 的 RSA 模数只有 " + modulusBits
                    + " 位，最低要求 2048 位");
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
            return new KeyEntry(kid, KeyType.RSA, privateKey, publicKey, info, null);
        }

        /**
         * P-256 密钥（{@code ECDH-ES}）：私钥 PKCS#8、公钥 SPKI，两条都必须落在 secp256r1 上。
         */
        private KeyEntry ecEntry(String kid, String privPkcs8Base64, String pubX509Base64) throws Exception {
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
            return new KeyEntry(kid, KeyType.EC, privateKey, publicKey, info, null);
        }

        /** 两条密钥的曲线参数都必须等于 P-256（secp256r1），否则拒绝（防降级到 P-384/P-521）。 */
        private static void requireP256(String kid, ECParameterSpec privParams, ECParameterSpec pubParams)
            throws Exception {
            ECParameterSpec p256 = p256Params();
            if (!p256.equals(privParams) || !p256.equals(pubParams)) {
                throw new EncryptorException("密钥 kid=" + kid + " 的曲线不是 P-256（secp256r1）");
            }
        }

        private static ECParameterSpec p256Params() {
            return P256Holder.INSTANCE;
        }

        /** P-256 参数与 JVM 无关且不可变，按需初始化一次即可（避免每把 EC 密钥都查 AlgorithmParameters）。 */
        private static final class P256Holder {
            private static final ECParameterSpec INSTANCE = load();

            private static ECParameterSpec load() {
                try {
                    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                    parameters.init(new ECGenParameterSpec("secp256r1"));
                    return parameters.getParameterSpec(ECParameterSpec.class);
                } catch (Exception e) {
                    throw new IllegalStateException("无法初始化 P-256（secp256r1）曲线参数", e);
                }
            }
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
            Map<String, KeyEntry> finalEntries = new LinkedHashMap<>(entries.size());
            for (Map.Entry<String, KeyEntry> item : entries.entrySet()) {
                KeyEntry entry = item.getValue();
                boolean active = item.getKey().equals(activeKid);
                PublicKeyInfo old = entry.publicKeyInfo();
                KeyEntry current = active == old.active() ? entry
                    : entry.withPublicKeyInfo(new PublicKeyInfo(old.kid(), old.alg(), old.spkiBase64(),
                        old.jwk(), active));
                finalEntries.put(item.getKey(), current);
            }
            return new ServerKeyStore(finalEntries, activeKid);
        }
    }
}
