package io.github.cuukenn.encryptor.jose;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 单机内存版 nonce 存储：带过期时间 + 容量上限的 {@link ConcurrentHashMap}。
 *
 * <p>"查重 + 写入"必须是一次原子操作（{@link ConcurrentMap#compute}），否则并发下同一个 nonce 会被多个线程同时放行。
 *
 * <p>本类只做单机防重放；多实例部署请实现 {@link NonceChecker} 换成共享存储。
 *
 * @author changgg
 */
public class InMemoryNonceStore implements NonceChecker {

    private final ConcurrentMap<String, Entry> caches = new ConcurrentHashMap<>();
    /** nonce 保留时长（毫秒），必须 ≥ 报文时间窗，否则同一 nonce 在窗口内可被复用。 */
    private final long retentionMillis;
    /** 容量上限：超限先清过期项，仍超限则按迭代顺序丢弃最旧项。 */
    private final int capacity;

    public InMemoryNonceStore(long retentionMillis, int capacity) {
        if (retentionMillis <= 0) {
            throw new IllegalArgumentException("retentionMillis must be positive");
        }
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.retentionMillis = retentionMillis;
        this.capacity = capacity;
    }

    @Override
    public boolean consume(String nonce) {
        if (nonce == null) {
            return false;
        }
        long now = System.currentTimeMillis();
        Entry candidate = new Entry(now + retentionMillis);
        // compute 把"判断 + 写入"合成一次原子操作：并发下同一个 nonce 只有一个线程能拿回自己写入的实例
        Entry stored = caches.compute(nonce, (key, old) -> old == null || old.isExpired(now) ? candidate : old);
        boolean first = stored == candidate;
        if (first) {
            evictIfNeeded(now);
        }
        return first;
    }

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
