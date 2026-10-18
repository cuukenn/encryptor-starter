package io.github.cuukenn.encryptor.protocol;

import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.jose.EcCipherSuite;
import io.github.cuukenn.encryptor.jose.JceCipherSuite;
import io.github.cuukenn.encryptor.jose.InMemoryNonceStore;
import io.github.cuukenn.encryptor.jose.JweCodec;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.jose.KeyType;
import io.github.cuukenn.encryptor.jose.NonceChecker;
import io.github.cuukenn.encryptor.jose.ReplayGuard;
import io.github.cuukenn.encryptor.jose.ServerKeyStore;
import io.github.cuukenn.encryptor.jose.SmCipherSuite;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 默认协议栈组装（纯 Java，无 Spring）：密钥库 + 编解码器 + 防重放 + 运行期开关。
 *
 * <p>两侧自动装配只 {@code new} 它，算法栈不再各写一份。所有非法配置在这里 fail-fast，
 * 启动即失败而不是等到第一个请求。
 *
 * @author changgg
 */
public class DefaultProtocol {

    /** 默认防重放时间窗（毫秒）。 */
    public static final long DEFAULT_TTL_MILLIS = 5 * 60 * 1000L;
    /** 默认 nonce 记录容量（条）。 */
    public static final int DEFAULT_NONCE_CAPACITY = 100_000;

    private static final String ALG_RSA = "RSA-OAEP-256";
    private static final String ALG_SM2 = "SM2";
    private static final String ALG_ECDH_ES = "ECDH-ES";
    private static final String ENC_DEFAULT = "A256GCM";
    private static final String ENC_SM4_GCM = "SM4-GCM";

    private final ServerKeyStore keys;
    private final JweCodec codec;
    private final ReplayGuard replayGuard;
    private final NonceChecker nonceChecker;
    private final EncryptorRuntime runtime;
    private final Set<String> allowedAlgs;
    private final Set<String> allowedEncs;
    private final long ttlMillis;

    private DefaultProtocol(Builder builder, ServerKeyStore keys, JweCodec codec,
                            ReplayGuard replayGuard, NonceChecker nonceChecker,
                            EncryptorRuntime runtime, Set<String> allowedAlgs, Set<String> allowedEncs) {
        this.keys = keys;
        this.codec = codec;
        this.replayGuard = replayGuard;
        this.nonceChecker = nonceChecker;
        this.runtime = runtime;
        this.allowedAlgs = allowedAlgs;
        this.allowedEncs = allowedEncs;
        this.ttlMillis = builder.ttlMillis;
    }

    public ServerKeyStore keys() {
        return keys;
    }

    public JweCodec codec() {
        return codec;
    }

    public ReplayGuard replayGuard() {
        return replayGuard;
    }

    /** nonce 存储（默认内存实现）。 */
    public NonceChecker nonceChecker() {
        return nonceChecker;
    }

    public EncryptorRuntime runtime() {
        return runtime;
    }

    public Set<String> allowedAlgs() {
        return allowedAlgs;
    }

    public Set<String> allowedEncs() {
        return allowedEncs;
    }

    public long ttlMillis() {
        return ttlMillis;
    }

    /** 便捷方法：解请求 + 防重放，一步到位（两侧过滤器共用）。 */
    public JweContext openRequest(String compactJwe, String uri, String method) {
        JweContext context = codec.decryptRequest(compactJwe, uri, method);
        replayGuard.verify(context.ts(), context.nonce());
        return context;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** 一把服务端密钥（kid + 类型 + base64 的 PKCS#8 私钥与 SPKI/PKCS#8 公钥，或 SM2 裸公钥）。 */
    public static final class KeyMaterial {

        private final String kid;
        private final KeyType type;
        private final String privateKeyB64;
        private final String publicKeyB64;

        public KeyMaterial(String kid, KeyType type, String privateKeyB64, String publicKeyB64) {
            this.kid = kid;
            this.type = type;
            this.privateKeyB64 = privateKeyB64;
            this.publicKeyB64 = publicKeyB64;
        }

        public String kid() {
            return kid;
        }

        public KeyType type() {
            return type;
        }

        public String privateKeyB64() {
            return privateKeyB64;
        }

        public String publicKeyB64() {
            return publicKeyB64;
        }
    }

    /** nonce 存储与检查器（默认内存实现，starter 可注入 bean 替换）。 */
    public static final class Builder {

        private final List<KeyMaterial> materials = new ArrayList<>();
        private String activeKid;
        private Set<String> allowedAlgs;
        private Set<String> allowedEncs;
        private long ttlMillis = DEFAULT_TTL_MILLIS;
        private long nonceRetentionMillis = -1L;
        private int nonceCapacity = DEFAULT_NONCE_CAPACITY;
        private NonceChecker nonceChecker;
        private EncryptorListener listener = EncryptorListener.NONE;
        private EncryptorRuntime runtime = new EncryptorRuntime();

        public Builder key(KeyMaterial material) {
            materials.add(material);
            return this;
        }

        public Builder keys(Collection<KeyMaterial> keys) {
            materials.addAll(keys);
            return this;
        }

        public Builder activeKid(String kid) {
            this.activeKid = kid;
            return this;
        }

        public Builder allowedAlgs(Set<String> algs) {
            this.allowedAlgs = algs;
            return this;
        }

        public Builder allowedEncs(Set<String> encs) {
            this.allowedEncs = encs;
            return this;
        }

        public Builder ttlMillis(long ttlMillis) {
            this.ttlMillis = ttlMillis;
            return this;
        }

        public Builder nonceRetentionMillis(long nonceRetentionMillis) {
            this.nonceRetentionMillis = nonceRetentionMillis;
            return this;
        }

        public Builder nonceCapacity(int nonceCapacity) {
            this.nonceCapacity = nonceCapacity;
            return this;
        }

        /**
         * 自定义 nonce 存储（多实例部署换共享存储，如 Redis）；不设置则用单机内存实现。
         */
        public Builder nonceChecker(NonceChecker nonceChecker) {
            this.nonceChecker = nonceChecker;
            return this;
        }

        public Builder listener(EncryptorListener listener) {
            this.listener = listener == null ? EncryptorListener.NONE : listener;
            return this;
        }

        public Builder runtime(EncryptorRuntime runtime) {
            this.runtime = runtime;
            return this;
        }

        public DefaultProtocol build() {
            if (materials.isEmpty()) {
                throw new EncryptorException("没有配置任何密钥（encryptor.config.keys）");
            }
            String active = activeKid == null || activeKid.isEmpty()
                ? materials.get(0).kid() : activeKid;
            boolean anyMatch = false;
            for (KeyMaterial material : materials) {
                if (active.equals(material.kid())) {
                    anyMatch = true;
                    break;
                }
            }
            if (!anyMatch) {
                throw new EncryptorException("active-kid 不存在: " + active);
            }
            if (ttlMillis <= 0) {
                ttlMillis = DEFAULT_TTL_MILLIS;
            }

            ServerKeyStore.Builder keys = ServerKeyStore.builder();
            Set<String> algs = new LinkedHashSet<>();
            boolean hasRsa = false;
            boolean hasSm2 = false;
            boolean hasEc = false;
            for (KeyMaterial material : materials) {
                keys.add(material.kid(), material.privateKeyB64(), material.publicKeyB64(), material.type());
                if (material.type() == KeyType.RSA) {
                    algs.add(ALG_RSA);
                    hasRsa = true;
                } else if (material.type() == KeyType.EC) {
                    algs.add(ALG_ECDH_ES);
                    hasEc = true;
                } else {
                    algs.add(ALG_SM2);
                    hasSm2 = true;
                }
            }
            keys.activeKid(active);
            ServerKeyStore store = keys.build();

            Set<String> effectiveAlgs = allowedAlgs == null || allowedAlgs.isEmpty()
                ? Collections.unmodifiableSet(algs) : Collections.unmodifiableSet(new LinkedHashSet<>(allowedAlgs));
            Set<String> effectiveEncs;
            if (allowedEncs == null || allowedEncs.isEmpty()) {
                // 默认 enc 跟密钥类型联动：有 SM2 密钥就必须接受 SM4-GCM，
                // 否则国密请求每个都 DECRYPT_FAILED（CEK 16B ≠ A256GCM 需要的 32B）
                Set<String> defaults = new LinkedHashSet<>();
                if (hasRsa || hasEc || !hasSm2) {
                    defaults.add(ENC_DEFAULT);
                }
                if (hasSm2) {
                    defaults.add(ENC_SM4_GCM);
                }
                effectiveEncs = Collections.unmodifiableSet(defaults);
            } else {
                effectiveEncs = Collections.unmodifiableSet(new LinkedHashSet<>(allowedEncs));
                if (hasSm2 && !effectiveEncs.contains(ENC_SM4_GCM)) {
                    throw new EncryptorException("配置了 SM2 密钥但 allowed-encs 不含 " + ENC_SM4_GCM
                        + "，国密请求必然解密失败（当前: " + effectiveEncs + "）");
                }
            }

            JweCodec codec = new JweCodec(store,
                Arrays.asList(new JceCipherSuite(), new EcCipherSuite(), new SmCipherSuite()),
                effectiveAlgs, effectiveEncs, listener);
            long retention = nonceRetentionMillis <= 0 ? ttlMillis : nonceRetentionMillis;
            NonceChecker effectiveNonceChecker = nonceChecker != null
                ? nonceChecker : new InMemoryNonceStore(retention, nonceCapacity);
            ReplayGuard guard = new ReplayGuard(ttlMillis, effectiveNonceChecker);
            return new DefaultProtocol(this, store, codec, guard, effectiveNonceChecker, runtime, effectiveAlgs, effectiveEncs);
        }
    }
}
