package io.github.cuukenn.encryptor.config.base;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * v2 协议通用配置的纯模型：不含 Spring 注解，也不依赖 servlet/reactive。
 *
 * <p>两侧的 {@code EncryptorConfig} 只保留各自的 {@code @ConfigurationProperties} 前缀，
 * 字段、默认值与 getter/setter 全部继承本类，避免双写漂移。</p>
 *
 * @param <K> 密钥配置类型
 * @param <B> 旁路配置类型
 * @param <D> 发现端点配置类型
 * @author changgg
 */
public abstract class EncryptorConfigBase<K extends KeyMaterialConfigBase,
    B extends BypassConfigBase, D extends DiscoveryConfigBase> {

    /**
     * 服务端密钥清单（至少一把；多钥并存支持轮换）。
     */
    private List<K> keys = new ArrayList<>();
    /**
     * 默认使用的 kid；不填取 keys 第一把。
     */
    private String activeKid;
    /**
     * 请求方向 alg 白名单；空 = 按密钥类型联动（RSA→RSA-OAEP-256，EC→ECDH-ES，SM2→SM2）。
     */
    private List<String> allowedAlgs = new ArrayList<>();
    /**
     * 请求方向 enc 白名单；空 = 按密钥类型联动（默认 A256GCM，SM2 追加 SM4-GCM）。
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
     * 旁路开关初始值。
     */
    private B bypass;
    /**
     * JWKS 只读发现端点。
     */
    private D discovery;

    protected EncryptorConfigBase(B bypass, D discovery) {
        this.bypass = bypass;
        this.discovery = discovery;
    }

    public List<K> getKeys() {
        return keys;
    }

    public void setKeys(List<K> keys) {
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

    public B getBypass() {
        return bypass;
    }

    public void setBypass(B bypass) {
        this.bypass = bypass;
    }

    public D getDiscovery() {
        return discovery;
    }

    public void setDiscovery(D discovery) {
        this.discovery = discovery;
    }
}
