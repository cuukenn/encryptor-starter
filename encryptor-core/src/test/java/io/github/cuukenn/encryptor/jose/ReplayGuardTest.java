package io.github.cuukenn.encryptor.jose;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link ReplayGuard} 契约测试：时间窗 + nonce 一次性。
 *
 * <p>调用点必须保证本类在 <b>GCM tag 校验通过之后</b> 才被调用（见 {@code JweCodec#decryptRequest} 之后的编排），
 * 否则未认证的输入会污染 nonce 存储。
 *
 * @author changgg
 */
class ReplayGuardTest {

    private static final long TTL = 5_000L;

    private static ReplayGuard guard() {
        return new ReplayGuard(TTL, new InMemoryNonceStore(TTL * 4, 1000));
    }

    @Test
    void 窗口内通过() {
        assertDoesNotThrow(() -> guard().verify(System.currentTimeMillis(), "n1"));
    }

    @Test
    void 过去或未来超窗一律EXPIRED() {
        long now = System.currentTimeMillis();
        assertEquals(EncryptorFailure.EXPIRED, assertThrows(EncryptorException.class,
            () -> guard().verify(now - TTL - 1_000L, "n1")).failure(), "过去超窗必须失败");
        assertEquals(EncryptorFailure.EXPIRED, assertThrows(EncryptorException.class,
            () -> guard().verify(now + TTL + 1_000L, "n1")).failure(), "未来超窗必须失败（时钟漂移不能成为绕过手段）");
    }

    @Test
    void 超窗的请求不占用nonce() {
        ReplayGuard guard = guard();
        long ts = System.currentTimeMillis();
        assertThrows(EncryptorException.class, () -> guard.verify(ts - TTL - 1_000L, "n1"));
        assertDoesNotThrow(() -> guard.verify(ts, "n1"), "过期垃圾请求不应占用 nonce 缓存");
    }

    @Test
    void 同一个nonce第二次一律REPLAY() {
        ReplayGuard guard = guard();
        long ts = System.currentTimeMillis();
        guard.verify(ts, "n1");
        assertEquals(EncryptorFailure.REPLAY, assertThrows(EncryptorException.class,
            () -> guard.verify(ts, "n1")).failure());
    }

    @Test
    void nonce超过上限一律拒绝() {
        StringBuilder nonce = new StringBuilder(129);
        for (int i = 0; i < 129; i++) {
            nonce.append('a');
        }
        assertEquals(EncryptorFailure.BAD_HEADER, assertThrows(EncryptorException.class,
            () -> guard().verify(System.currentTimeMillis(), nonce.toString())).failure());
    }

    @Test
    void 缺nonce一律拒绝() {
        assertEquals(EncryptorFailure.BAD_HEADER,
            assertThrows(EncryptorException.class, () -> guard().verify(System.currentTimeMillis(), null)).failure());
        assertEquals(EncryptorFailure.BAD_HEADER,
            assertThrows(EncryptorException.class, () -> guard().verify(System.currentTimeMillis(), "")).failure());
    }

    @Test
    void 并发同一nonce只有一个通过() throws Exception {
        ReplayGuard guard = guard();
        int threads = 100;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger passed = new AtomicInteger();
        long ts = System.currentTimeMillis();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    guard.verify(ts, "same-nonce");
                    passed.incrementAndGet();
                } catch (EncryptorException expected) {
                    // 其余线程必须被判为重放
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS), "并发任务必须全部结束");
        pool.shutdownNow();
        assertEquals(1, passed.get(), "同一个 nonce 并发只能有一个请求通过");
    }

    @Test
    void long溢出的极端时间戳必须EXPIRED() {
        // Math.abs(now - ts) 口径下：ts = now + Long.MIN_VALUE 时差值溢出为 Long.MIN_VALUE，
        // abs 仍为负，超窗判定被跳过——必须用双端比较堵死
        long now = System.currentTimeMillis();
        assertEquals(EncryptorFailure.EXPIRED, assertThrows(EncryptorException.class,
            () -> guard().verify(now + Long.MIN_VALUE, "n1")).failure());
    }

    @Test
    void retention不足2倍ttl的内存nonce存储在构造期拒绝() {
        assertThrows(IllegalArgumentException.class,
            () -> new ReplayGuard(TTL, new InMemoryNonceStore(TTL * 2 - 1, 1000)),
            "retention < 2*ttl 存在未来时间戳重放缺口，必须构造期失败");
        assertDoesNotThrow(() -> new ReplayGuard(TTL, new InMemoryNonceStore(TTL * 2, 1000)));
    }
}
