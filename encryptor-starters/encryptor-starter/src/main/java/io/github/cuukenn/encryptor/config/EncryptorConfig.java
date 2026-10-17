package io.github.cuukenn.encryptor.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * v2 协议配置（前缀 {@code encryptor.config}）。
 *
 * @author changgg
 */
@ConfigurationProperties(prefix = EncryptorConfig.PREFIX)
public class EncryptorConfig {
    public static final String PREFIX = "encryptor.config";

    /**
     * 服务端密钥清单（至少一把；多钥并存支持轮换）。
     */
    private List<KeyMaterialConfig> keys = new ArrayList<>();
    /**
     * 默认使用的 kid；不填取 keys 第一把。
     */
    private String activeKid;
    /**
     * 请求方向 alg 白名单；空 = 按密钥类型联动（RSA→RSA-OAEP-256，SM2→SM2）。
     * 白名单在 JweCodec 内强制，客户端不可自选。
     */
    private List<String> allowedAlgs = new ArrayList<>();
    /**
     * 请求方向 enc 白名单；空 = 默认 {A256GCM}。
     */
    private List<String> allowedEncs = new ArrayList<>();
    /**
     * 防重放时间窗（ts 与 now 的允许偏差）。
     */
    private Duration ttl = Duration.ofMinutes(5);
    /**
     * nonce 记录保留时长；空 = 跟随 ttl。
     */
    private Duration nonceRetention;
    /**
     * nonce 记录容量上限（内存实现）。
     */
    private int nonceCapacity = 100_000;
    /**
     * 报文非法（解不开 / 重放 / 白名单外算法）时返回的 HTTP 状态码。
     */
    private int failureStatus = 400;
    /**
     * 请求体大小上限（字节），默认 1MiB；{@code <= 0} 不限制。
     */
    private long maxRequestSize = 1048576L;
    /**
     * 响应体加密前的大小上限（字节），默认 4MiB；超限 500 + 日志，不发明文。
     */
    private long maxResponseSize = 4194304L;
    /**
     * 命中范围的请求是否必须携带合法 jwe（默认 true：缺 jwe ⇒ failure-status，fail-closed）。
     */
    private boolean requireEncrypted = true;
    /**
     * 旁路开关初始值（运行期可经 EncryptorRuntime 热改）。
     */
    @NestedConfigurationProperty
    private BypassConfig bypass = new BypassConfig();
    /**
     * JWKS 只读发现端点。
     */
    @NestedConfigurationProperty
    private DiscoveryConfig discovery = new DiscoveryConfig();
    /**
     * v1 遗留配置，仅在 T9/T10 重接传输层前占位；新协议不再读取。
     */
    @Deprecated
    @NestedConfigurationProperty
    private CryptoConfig cryptoConfig = new CryptoConfig();

    public List<KeyMaterialConfig> getKeys() {
        return keys;
    }

    public void setKeys(List<KeyMaterialConfig> keys) {
        this.keys = keys;
    }

    public String getActiveKid() {
        return activeKid;
    }

    public void setActiveKid(String activeKid) {
        this.activeKid = activeKid;
    }

    public List<String> getAllowedAlgs() {
        return allowedAlgs;
    }

    public void setAllowedAlgs(List<String> allowedAlgs) {
        this.allowedAlgs = allowedAlgs;
    }

    public List<String> getAllowedEncs() {
        return allowedEncs;
    }

    public void setAllowedEncs(List<String> allowedEncs) {
        this.allowedEncs = allowedEncs;
    }

    public Duration getTtl() {
        return ttl;
    }

    public void setTtl(Duration ttl) {
        this.ttl = ttl;
    }

    public Duration getNonceRetention() {
        return nonceRetention;
    }

    public void setNonceRetention(Duration nonceRetention) {
        this.nonceRetention = nonceRetention;
    }

    public int getNonceCapacity() {
        return nonceCapacity;
    }

    public void setNonceCapacity(int nonceCapacity) {
        this.nonceCapacity = nonceCapacity;
    }

    public int getFailureStatus() {
        return failureStatus;
    }

    public void setFailureStatus(int failureStatus) {
        this.failureStatus = failureStatus;
    }

    public long getMaxRequestSize() {
        return maxRequestSize;
    }

    public void setMaxRequestSize(long maxRequestSize) {
        this.maxRequestSize = maxRequestSize;
    }

    public long getMaxResponseSize() {
        return maxResponseSize;
    }

    public void setMaxResponseSize(long maxResponseSize) {
        this.maxResponseSize = maxResponseSize;
    }

    public boolean isRequireEncrypted() {
        return requireEncrypted;
    }

    public void setRequireEncrypted(boolean requireEncrypted) {
        this.requireEncrypted = requireEncrypted;
    }

    public BypassConfig getBypass() {
        return bypass;
    }

    public void setBypass(BypassConfig bypass) {
        this.bypass = bypass;
    }

    public DiscoveryConfig getDiscovery() {
        return discovery;
    }

    public void setDiscovery(DiscoveryConfig discovery) {
        this.discovery = discovery;
    }

    @Deprecated
    public CryptoConfig getCryptoConfig() {
        return cryptoConfig;
    }

    @Deprecated
    public void setCryptoConfig(CryptoConfig cryptoConfig) {
        this.cryptoConfig = cryptoConfig;
    }
}
