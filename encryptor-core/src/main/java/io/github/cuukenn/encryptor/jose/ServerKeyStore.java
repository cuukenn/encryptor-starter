package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import io.github.cuukenn.encryptor.exception.EncryptorException;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 服务端密钥库：多 {@code kid} 并存（支持轮换），按 {@code kid} 取私钥、导出只含公钥的 JWK 与 SPKI。
 *
 * <p>构建后完全不可变 —— 线程安全由不可变性保证，内部不持有任何共享可变状态
 * （尤其不缓存 {@code Cipher}：{@code Cipher} 非线程安全，缓存单实例会把 RSA 运算全局串行化）。
 *
 * @author changgg
 */
public final class ServerKeyStore {

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
     * 单密钥便捷构造。
     *
     * @param kid           密钥标识
     * @param privPkcs8Base64 私钥（PKCS#8 DER 的 base64）
     * @param pubX509Base64  公钥（X.509 SubjectPublicKeyInfo 的 base64）
     * @param active         是否设为当前推荐 kid
     */
    public static ServerKeyStore fromBase64(String kid, String privPkcs8Base64, String pubX509Base64, boolean active) {
        Builder builder = builder().add(kid, privPkcs8Base64, pubX509Base64);
        if (active) {
            builder.activeKid(kid);
        }
        return builder.build();
    }

    public boolean contains(String kid) {
        return entries.containsKey(kid);
    }

    /** 未知 kid 返回 {@code null}（由调用方决定错误面）。 */
    public PrivateKey privateKey(String kid) {
        Entry entry = entries.get(kid);
        return entry == null ? null : entry.privateKey;
    }

    /** 未知 kid 返回 {@code null}。 */
    public PublicKey publicKey(String kid) {
        Entry entry = entries.get(kid);
        return entry == null ? null : entry.publicKey;
    }

    /** 供 JWE 解码器使用的 nimbus 密钥（含私钥）；未知 kid 返回 {@code null}。 */
    public RSAKey rsaKey(String kid) {
        Entry entry = entries.get(kid);
        return entry == null ? null : entry.rsaKey;
    }

    public String activeKid() {
        return activeKid;
    }

    /** X.509 SubjectPublicKeyInfo 的 base64（不含 PEM 头尾）；未知 kid 返回 {@code null}。 */
    public String spkiBase64(String kid) {
        Entry entry = entries.get(kid);
        return entry == null ? null : entry.spkiBase64;
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
        private final PrivateKey privateKey;
        private final PublicKey publicKey;
        private final RSAKey rsaKey;
        private final String spkiBase64;
        private final PublicKeyInfo publicKeyInfo;

        private Entry(String kid, PrivateKey privateKey, PublicKey publicKey,
                      RSAKey rsaKey, String spkiBase64, boolean active) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.rsaKey = rsaKey;
            this.spkiBase64 = spkiBase64;
            this.publicKeyInfo = new PublicKeyInfo(kid, JWEAlgorithm.RSA_OAEP_256.getName(), spkiBase64,
                rsaKey.toPublicJWK().toJSONObject(), active);
        }
    }

    public static final class Builder {
        private final Map<String, Entry> entries = new LinkedHashMap<>();
        private String activeKid;

        /**
         * 添加一把密钥；解析失败立刻抛出（fail-fast，不等第一个请求）。
         */
        public Builder add(String kid, String privPkcs8Base64, String pubX509Base64) {
            if (kid == null || kid.isEmpty()) {
                throw new EncryptorException("密钥 kid 不能为空");
            }
            if (entries.containsKey(kid)) {
                throw new EncryptorException("密钥 kid 重复: " + kid);
            }
            try {
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
                entries.put(kid, new Entry(kid, privateKey, publicKey, rsaKey,
                    Base64.getEncoder().encodeToString(publicKey.getEncoded()), false));
            } catch (EncryptorException e) {
                throw e;
            } catch (Exception e) {
                throw new EncryptorException("密钥 kid=" + kid + " 解析失败: " + e.getMessage(), e);
            }
            return this;
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
                finalEntries.put(item.getKey(), new Entry(item.getKey(), entry.privateKey, entry.publicKey,
                    entry.rsaKey, entry.spkiBase64, active));
            }
            return new ServerKeyStore(finalEntries, activeKid);
        }
    }
}
