package io.github.cuukenn.encryptor.jose;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 单机内存版 nonce 存储：带过期时间 + 容量上限的 {@link ConcurrentHashMap}。
 *
 * <p>"查重 + 写入"必须是一次原子操作（{@link ConcurrentMap#compute}），否则并发下同一个 nonce 会被多个线程同时放行。
 *
 * <p>容量上限的取舍：超限时按<b>插入顺序</b>驱逐最早的一批记录（保留期固定 ⇒ 插入顺序即最早过期顺序），
 * 并顺带清理已过期项。驱逐是 O(1) 摊销（插入队列 + 序号比对），不再按 map 迭代序随机丢，
 * 也消除了"每次 consume 全表扫描"的 CPU 放大。
 *
 * <p><b>安全边界</b>：公钥是公开的（设计内 non-goal），任何人可构造合法报文灌满容量；被驱逐的记录在
 * 时间窗内可再次使用（即重放）。容量越大越难挤掉，但单机内存实现终究可以被打穿——
 * 多实例部署或需要强防重放请实现本接口换共享存储（Redis 等）。
 *
 * @author changgg
 */
public class InMemoryNonceStore implements NonceChecker {

    private final ConcurrentMap<String, Entry> caches = new ConcurrentHashMap<>();
    /** 插入顺序（与过期顺序一致），用于容量驱逐；与 caches 的一致性由 lock 保护。 */
    private final Deque<OrderRecord> order = new ArrayDeque<>();
    private final Object lock = new Object();
    private final AtomicLong sequence = new AtomicLong();
    private final AtomicLong evicted = new AtomicLong();
    /** nonce 保留时长（毫秒），必须 ≥ 报文时间窗，否则同一 nonce 在窗口内可被复用。 */
    private final long retentionMillis;
    /** 容量上限：超限按插入顺序驱逐最早项（并顺带清理过期项）。 */
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
        Entry candidate = new Entry(now + retentionMillis, sequence.incrementAndGet());
        // compute 把"判断 + 写入"合成一次原子操作：并发下同一个 nonce 只有一个线程能拿回自己写入的实例
        Entry stored = caches.compute(nonce, (key, old) -> old == null || old.isExpired(now) ? candidate : old);
        boolean first = stored == candidate;
        if (first) {
            evictIfNeeded(nonce, candidate, now);
        }
        return first;
    }

    /** 已驱逐的记录数（可观测性：被灌满的迹象）。 */
    public long evictedCount() {
        return evicted.get();
    }

    private void evictIfNeeded(String nonce, Entry entry, long now) {
        synchronized (lock) {
            order.addLast(new OrderRecord(nonce, entry.sequence));
            while (order.size() > capacity) {
                removeHead(now);
            }
            // 插入顺序 == 过期顺序：队首过期即整批过期，顺带回收
            while (!order.isEmpty()) {
                OrderRecord head = order.peekFirst();
                Entry current = caches.get(head.nonce);
                if (current == null || current.sequence != head.sequence || current.isExpired(now)) {
                    order.pollFirst();
                    if (current != null && current.sequence == head.sequence) {
                        caches.remove(head.nonce);
                    }
                } else {
                    break;
                }
            }
        }
    }

    private void removeHead(long now) {
        OrderRecord head = order.pollFirst();
        if (head == null) {
            return;
        }
        Entry current = caches.get(head.nonce);
        // 只有当前记录仍是当初插入的那条才删除；已被过期后重新占用的新记录不能误删
        if (current != null && current.sequence == head.sequence) {
            caches.remove(head.nonce);
            evicted.incrementAndGet();
        }
    }

    private static final class Entry {
        private final long expireAt;
        private final long sequence;

        private Entry(long expireAt, long sequence) {
            this.expireAt = expireAt;
            this.sequence = sequence;
        }

        private boolean isExpired(long now) {
            return now >= expireAt;
        }
    }

    private static final class OrderRecord {
        private final String nonce;
        private final long sequence;

        private OrderRecord(String nonce, long sequence) {
            this.nonce = nonce;
            this.sequence = sequence;
        }
    }
}
