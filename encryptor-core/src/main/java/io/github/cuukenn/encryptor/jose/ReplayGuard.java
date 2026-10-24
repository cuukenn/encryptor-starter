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
        // 防重放缺口约束：nonce 保留期不足 2*ttl 时，窗口边界附近的 nonce 会被提前驱逐，
        // 形成"未来时间戳重放"缺口。该约束此前只在 DefaultProtocol.build() 拦截配置路径，
        // 这里对内存实现下沉到构造器兜底。
        if (nonceChecker instanceof InMemoryNonceStore
            && ((InMemoryNonceStore) nonceChecker).retentionMillis() < saturatedMultiply(ttlMillis, 2L)) {
            throw new IllegalArgumentException(
                "InMemoryNonceStore 的 retention 必须 ≥ 2*ttlMillis，否则时间窗边界存在重放缺口");
        }
        this.ttlMillis = ttlMillis;
        this.nonceChecker = nonceChecker;
    }

    /** 饱和乘法：ttl 取极端 long 值时 2*ttl 不再静默溢出为负。 */
    private static long saturatedMultiply(long value, long factor) {
        long r = value * factor;
        if (((value ^ r) & (factor ^ r)) < 0) {
            return Long.MAX_VALUE;
        }
        return r;
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
        // 不能用 Math.abs(now - ts)：ts = now + Long.MIN_VALUE 时差值溢出为 Long.MIN_VALUE，
        // abs 仍为负，超窗判定被跳过。改为双端比较（配合饱和加法，防御极端 ttl 的 now+ttl 溢出）。
        long lower = now - ttlMillis;
        long upper = saturatedAdd(now, ttlMillis);
        if (ts < lower || ts > upper) {
            throw JweCodec.fail(EncryptorFailure.EXPIRED,
                "报文时间戳超出窗口: ts=" + ts + ", now=" + now + ", ttl=" + ttlMillis);
        }
        JweCodec.validateNonce(nonce);
        // 时间窗先校验：过期的垃圾请求不应占用 nonce 存储
        if (!nonceChecker.consume(nonce)) {
            throw JweCodec.fail(EncryptorFailure.REPLAY, "nonce 已被使用（重放）");
        }
    }

    /** 饱和加法：now + ttl 在极端 ttl 下不静默回绕。 */
    private static long saturatedAdd(long a, long b) {
        long r = a + b;
        if (((a ^ r) & (b ^ r)) < 0) {
            return a < 0 ? Long.MIN_VALUE : Long.MAX_VALUE;
        }
        return r;
    }
}
