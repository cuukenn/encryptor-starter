package io.github.cuukenn.encryptor.jose;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;

/**
 * 防重放：时间窗（{@code ts}）+ nonce 一次性。
 *
 * <p><b>调用点约束</b>：必须在 GCM/SM4-GCM 的 tag 校验<b>通过之后</b>调用。否则攻击者可以拿未认证的
 * 报文把 victim 将来要用的 nonce 提前"占掉"（污染 nonce 存储），造成拒绝服务。
 *
 * <p>时间窗必须<b>对称</b>：只看"过去"的话，把 {@code ts} 写成未来即可绕过。
 *
 * @author changgg
 */
public class ReplayGuard {

    private final long ttlMillis;
    private final NonceChecker nonceChecker;

    /**
     * @param ttlMillis    允许的时间偏移（毫秒，必须为正）
     * @param nonceChecker nonce 一次性校验器
     */
    public ReplayGuard(long ttlMillis, NonceChecker nonceChecker) {
        if (ttlMillis <= 0) {
            throw new IllegalArgumentException("ttlMillis must be positive");
        }
        if (nonceChecker == null) {
            throw new IllegalArgumentException("nonceChecker must not be null");
        }
        this.ttlMillis = ttlMillis;
        this.nonceChecker = nonceChecker;
    }

    public long ttlMillis() {
        return ttlMillis;
    }

    /**
     * 校验时间窗与 nonce。
     *
     * @throws EncryptorException {@link EncryptorFailure#EXPIRED} 超窗；{@link EncryptorFailure#BAD_HEADER}
     *                            缺 nonce；{@link EncryptorFailure#REPLAY} 重放
     */
    public void verify(long ts, String nonce) {
        long now = System.currentTimeMillis();
        if (Math.abs(now - ts) >= ttlMillis) {
            throw JweCodec.fail(EncryptorFailure.EXPIRED,
                "报文时间戳超出窗口: ts=" + ts + ", now=" + now + ", ttl=" + ttlMillis);
        }
        if (nonce == null || nonce.isEmpty()) {
            throw JweCodec.fail(EncryptorFailure.BAD_HEADER, "报文缺少 nonce");
        }
        // 时间窗先校验：过期的垃圾请求不应占用 nonce 存储
        if (!nonceChecker.consume(nonce)) {
            throw JweCodec.fail(EncryptorFailure.REPLAY, "nonce 已被使用（重放）");
        }
    }
}
