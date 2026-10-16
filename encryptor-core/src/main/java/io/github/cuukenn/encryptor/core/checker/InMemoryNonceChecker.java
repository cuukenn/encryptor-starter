package io.github.cuukenn.encryptor.core.checker;

import io.github.cuukenn.encryptor.core.CheckerStrategy;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;

import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 基于内存的 nonce 防重放校验器。
 *
 * <p>用 {@link ConcurrentHashMap} 自实现"带过期时间 + 容量上限"的存储。原来用的
 * {@code CacheUtil.newLRUCache} 不是线程安全的，而本类会被多线程共享（每个请求都会调用
 * {@link #check(EncryptorDataWrapper)}），"查重 + 写入"之间可被并发穿透。</p>
 *
 * <p>本类只做单机防重放，多实例部署请改用 {@code InRedisNonceChecker}。</p>
 *
 * @author changgg
 */
public class InMemoryNonceChecker implements CheckerStrategy {
    /**
     * nonce -> 过期时间（epoch millis）
     */
    private final ConcurrentMap<String, Entry> caches = new ConcurrentHashMap<>();
    /**
     * 容量上限，超过后先清理过期项，仍然超限则按迭代顺序丢弃
     */
    private final int capacity;
    private final Duration offsetDuration;

    public InMemoryNonceChecker(int capacity, Duration offsetDuration) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.capacity = capacity;
        this.offsetDuration = offsetDuration;
    }

    @Override
    public void check(EncryptorDataWrapper data) {
        final String nonce = data.getNonce();
        final Long timestamp = data.getTimestamp();
        if (timestamp == null) {
            throw new EncryptorException("request timestamp is missing");
        }
        // 时窗必须对称：只判断"过去"的话，客户端把时间戳写成未来即可绕过校验
        final long offsetMillis = offsetDuration.toMillis();
        final long now = System.currentTimeMillis();
        if (Math.abs(now - timestamp) >= offsetMillis) {
            throw new EncryptorException("request out of time or client time error");
        }
        if (nonce == null) {
            throw new EncryptorException("request nonce is missing");
        }
        // 时间戳校验放在重放校验之前：过期的垃圾请求不应该占用 nonce 缓存。
        // 用 compute 把"判断 + 写入"合成一次原子操作：并发下同一个 nonce 只会有一个线程
        // 拿到自己写入的 Entry 实例，其余线程拿到的都是已存在的 Entry（即判为重放）。
        final Entry entry = new Entry(now + offsetMillis);
        final Entry result = caches.compute(nonce, (key, old) -> old == null || old.isExpired(now) ? entry : old);
        if (result != entry) {
            throw new EncryptorException("request replay");
        }
        evictIfNeeded(now);
    }

    /**
     * 保持内存占用有上界：先清理已过期项，仍然超限时按迭代顺序丢弃。
     */
    private void evictIfNeeded(long now) {
        if (caches.size() <= capacity) {
            return;
        }
        caches.entrySet().removeIf(item -> item.getValue().isExpired(now));
        for (Iterator<Map.Entry<String, Entry>> iterator = caches.entrySet().iterator();
             iterator.hasNext() && caches.size() > capacity; ) {
            iterator.next();
            iterator.remove();
        }
    }

    private static final class Entry {
        private final long expireAt;

        private Entry(long expireAt) {
            this.expireAt = expireAt;
        }

        private boolean isExpired(long now) {
            return now >= expireAt;
        }
    }
}
