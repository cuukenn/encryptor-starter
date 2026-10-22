package io.github.cuukenn.encryptor.jose;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
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
 * <p>大容量会按 nonce 哈希分片，每个分片有独立的 map/队列/锁，降低高并发下的全局锁竞争；
 * 总容量按分片精确分配，全局记录数仍不超过构造时的 capacity。分片内按插入顺序驱逐，
 * 因此"全局最早项"语义在大容量下退化为"分片内最早项"。小容量（&lt; 1024）保持单分片，
 * 维持严格的全局插入顺序。
 *
 * <p><b>安全边界</b>：公钥是公开的（设计内 non-goal），任何人可构造合法报文灌满容量；被驱逐的记录在
 * 时间窗内可再次使用（即重放）。容量越大越难挤掉，但单机内存实现终究可以被打穿——
 * 多实例部署或需要强防重放请实现本接口换共享存储（Redis 等）。
 *
 * @author changgg
 */
public class InMemoryNonceStore implements NonceChecker {

    private static final Logger log = LoggerFactory.getLogger(InMemoryNonceStore.class);

    /** 分片数上限：足够抵消全局锁竞争，又避免小容量被切得过碎。 */
    private static final int MAX_SHARDS = 16;
    /** 单个分片的最小目标容量；容量太小就减少分片数。 */
    private static final int MIN_SEGMENT_CAPACITY = 64;
    /** 低于该容量保持单分片，维持现有的全局插入顺序契约。 */
    private static final int SHARD_THRESHOLD = 1024;

    private final Segment[] segments;
    /** 进程内随机哈希种子：nonce 由客户端提供，加盐避免攻击者定向打爆某一个分片。 */
    private final int hashSeed = ThreadLocalRandom.current().nextInt();
    private final long retentionMillis;
    private final int capacity;
    private final AtomicBoolean evictionWarned = new AtomicBoolean();

    public InMemoryNonceStore(long retentionMillis, int capacity) {
        this(retentionMillis, capacity, defaultShards(capacity));
    }

    /**
     * 显式指定分片数（包内可见，便于测试和后续调优）。
     *
     * @param retentionMillis nonce 保留时长（毫秒）
     * @param capacity        全局容量上限
     * @param shards          分片数，必须落在 {@code [1, capacity]}
     */
    InMemoryNonceStore(long retentionMillis, int capacity, int shards) {
        if (retentionMillis <= 0) {
            throw new IllegalArgumentException("retentionMillis must be positive");
        }
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        if (shards <= 0 || shards > capacity) {
            throw new IllegalArgumentException("shards must be in [1, capacity]");
        }
        this.segments = new Segment[shards];
        this.retentionMillis = retentionMillis;
        this.capacity = capacity;
        int base = capacity / shards;
        int remainder = capacity % shards;
        for (int i = 0; i < shards; i++) {
            this.segments[i] = new Segment(retentionMillis, base + (i < remainder ? 1 : 0));
        }
    }

    @Override
    public boolean consume(String nonce) {
        if (nonce == null) {
            return false;
        }
        boolean first = segmentFor(nonce).consume(nonce);
        if (first && !evictionWarned.get() && evictedCount() > 0 && evictionWarned.compareAndSet(false, true)) {
            log.warn("nonce 存储达到容量上限，开始驱逐窗口内记录（capacity={}, retention={}ms）："
                + "被驱逐的 nonce 在时间窗内可再次使用，即存在重放缺口；请调大 nonce-capacity 或改用共享存储",
                capacity, retentionMillis);
        }
        return first;
    }

    /** 已驱逐的记录数（可观测性：被灌满的迹象）。 */
    public long evictedCount() {
        long total = 0L;
        for (Segment segment : segments) {
            total += segment.evictedCount();
        }
        return total;
    }

    /** 当前保留的记录数（观测用；并发写入时是弱一致快照）。 */
    public int size() {
        int total = 0;
        for (Segment segment : segments) {
            total += segment.size();
        }
        return total;
    }

    /** 当前分片数（观测/测试用）。 */
    int shardCount() {
        return segments.length;
    }

    private Segment segmentFor(String nonce) {
        int hash = (nonce.hashCode() ^ hashSeed) & 0x7fffffff;
        return segments[hash % segments.length];
    }

    private static int defaultShards(int capacity) {
        if (capacity < SHARD_THRESHOLD) {
            return 1;
        }
        int shards = MAX_SHARDS;
        while (shards > 1 && capacity / shards < MIN_SEGMENT_CAPACITY) {
            shards >>= 1;
        }
        return shards;
    }

    /**
     * 单个分片：保留原有"compute 原子占位 + 插入队列驱逐"的实现，锁只保护本分片。
     */
    private static final class Segment {

        private final ConcurrentMap<String, Entry> caches = new ConcurrentHashMap<>();
        /** 插入顺序（与过期顺序一致），用于容量驱逐；与 caches 的一致性由 lock 保护。 */
        private final Deque<OrderRecord> order = new ArrayDeque<>();
        private final Object lock = new Object();
        private final AtomicLong sequence = new AtomicLong();
        private final AtomicLong evicted = new AtomicLong();
        private final long retentionMillis;
        private final int capacity;

        private Segment(long retentionMillis, int capacity) {
            this.retentionMillis = retentionMillis;
            this.capacity = capacity;
        }

        private boolean consume(String nonce) {
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

        private long evictedCount() {
            return evicted.get();
        }

        private int size() {
            return caches.size();
        }

        private void evictIfNeeded(String nonce, Entry entry, long now) {
            synchronized (lock) {
                order.addLast(new OrderRecord(nonce, entry.sequence));
                while (order.size() > capacity) {
                    removeHead();
                }
                // 插入顺序 == 过期顺序：队首过期即整批过期，顺带回收
                while (!order.isEmpty()) {
                    OrderRecord head = order.peekFirst();
                    Entry current = caches.get(head.nonce);
                    if (current == null || current.sequence != head.sequence || current.isExpired(now)) {
                        order.pollFirst();
                        if (current != null && current.sequence == head.sequence) {
                            // 条件删除：读取后若同 nonce 已被并发 compute 换成新记录，不能误删新记录
                            caches.remove(head.nonce, current);
                        }
                    } else {
                        break;
                    }
                }
            }
        }

        private void removeHead() {
            OrderRecord head = order.pollFirst();
            if (head == null) {
                return;
            }
            Entry current = caches.get(head.nonce);
            // 只有当前记录仍是当初插入的那条才删除；已被过期后重新占用的新记录不能误删
            if (current != null && current.sequence == head.sequence) {
                // 条件删除：避免 get 与 remove 之间被并发 compute 替换后误删新记录
                if (caches.remove(head.nonce, current)) {
                    evicted.incrementAndGet();
                }
            }
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
