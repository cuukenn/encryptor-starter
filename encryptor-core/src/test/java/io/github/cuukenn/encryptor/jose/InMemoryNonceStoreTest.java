package io.github.cuukenn.encryptor.jose;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link InMemoryNonceStore} 契约：原子占位、按插入顺序驱逐、过期可复用。
 *
 * @author changgg
 */
class InMemoryNonceStoreTest {

    @Test
    void 容量超限按插入顺序驱逐最早项() {
        InMemoryNonceStore store = new InMemoryNonceStore(60_000L, 2);
        assertTrue(store.consume("a"));
        assertTrue(store.consume("b"));
        assertTrue(store.consume("c"));
        assertTrue(store.consume("a"), "被驱逐的最早项应可再次消费（记录已不保留）");
        assertFalse(store.consume("c"), "最新项不应被驱逐");
    }

    @Test
    void 大容量自动分片且总容量仍受上限约束() {
        InMemoryNonceStore store = new InMemoryNonceStore(60_000L, 1024);
        assertTrue(store.shardCount() > 1, "大容量应分片以降低全局锁竞争");
        for (int i = 0; i < 4096; i++) {
            assertTrue(store.consume("n" + i));
        }
        assertTrue(store.size() <= 1024, "分片后总记录数仍不得超过容量上限");
        assertTrue(store.evictedCount() > 0, "超过容量后应发生驱逐");
    }

    @Test
    void 小容量保持单分片以维持全局插入顺序() {
        assertEquals(1, new InMemoryNonceStore(60_000L, 2).shardCount());
    }

    @Test
    void 驱逐计数可观测() {
        InMemoryNonceStore store = new InMemoryNonceStore(60_000L, 1);
        assertTrue(store.consume("a"));
        assertTrue(store.consume("b"));
        assertEquals(1L, store.evictedCount());
    }

    @Test
    void 记录过期后可再次消费() throws Exception {
        InMemoryNonceStore store = new InMemoryNonceStore(30L, 100);
        assertTrue(store.consume("a"));
        assertFalse(store.consume("a"));
        Thread.sleep(60L);
        assertTrue(store.consume("a"), "过期记录应被清理，同一 nonce 可再次占用");
    }

    @Test
    void 并发下同一nonce只有一个线程成功() throws Exception {
        InMemoryNonceStore store = new InMemoryNonceStore(60_000L, 1000);
        int threads = 8;
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicInteger success = new java.util.concurrent.atomic.AtomicInteger();
        java.util.List<Thread> pool = new java.util.ArrayList<>();
        for (int i = 0; i < threads; i++) {
            Thread t = new Thread(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                if (store.consume("same")) {
                    success.incrementAndGet();
                }
            });
            pool.add(t);
            t.start();
        }
        start.countDown();
        for (Thread t : pool) {
            t.join();
        }
        assertEquals(1, success.get(), "同一 nonce 只能成功占用一次");
    }
}
