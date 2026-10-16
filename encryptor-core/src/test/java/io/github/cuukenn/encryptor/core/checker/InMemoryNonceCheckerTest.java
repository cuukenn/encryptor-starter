package io.github.cuukenn.encryptor.core.checker;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * @author changgg
 */
public class InMemoryNonceCheckerTest {
    private static EncryptorDataWrapper wrapper(String nonce, Long timestamp) {
        EncryptorDataWrapper data = new EncryptorDataWrapper();
        data.setNonce(nonce);
        data.setTimestamp(timestamp);
        return data;
    }

    @Test
    public void test_replay_request_rejected() {
        InMemoryNonceChecker checker = new InMemoryNonceChecker(10, Duration.ofSeconds(30));
        long now = System.currentTimeMillis();
        checker.check(wrapper("nonce-1", now));
        Assertions.assertThrows(EncryptorException.class, () -> checker.check(wrapper("nonce-1", now)));
    }

    @Test
    public void test_future_timestamp_rejected() {
        InMemoryNonceChecker checker = new InMemoryNonceChecker(10, Duration.ofSeconds(30));
        // 只判断"过去"的实现会放过时间戳在未来的请求
        long future = System.currentTimeMillis() + Duration.ofMinutes(1).toMillis();
        Assertions.assertThrows(EncryptorException.class, () -> checker.check(wrapper("nonce-future", future)));
    }

    @Test
    public void test_expired_timestamp_rejected() {
        InMemoryNonceChecker checker = new InMemoryNonceChecker(10, Duration.ofSeconds(30));
        long expired = System.currentTimeMillis() - Duration.ofMinutes(1).toMillis();
        Assertions.assertThrows(EncryptorException.class, () -> checker.check(wrapper("nonce-expired", expired)));
    }

    @Test
    public void test_sub_second_offset_duration_is_not_truncated() {
        InMemoryNonceChecker checker = new InMemoryNonceChecker(10, Duration.ofMillis(1500L));
        // 1.5s 的窗口，1.1s 前的请求在窗口内；按秒截断的实现（窗口变成 1s）会误判为过期
        long withinWindow = System.currentTimeMillis() - 1100L;
        checker.check(wrapper("nonce-within-window", withinWindow));
    }

    @Test
    public void test_missing_timestamp_rejected() {
        InMemoryNonceChecker checker = new InMemoryNonceChecker(10, Duration.ofSeconds(30));
        Assertions.assertThrows(EncryptorException.class, () -> checker.check(wrapper("nonce-no-timestamp", null)));
    }

    @Test
    public void test_missing_nonce_rejected() {
        InMemoryNonceChecker checker = new InMemoryNonceChecker(10, Duration.ofSeconds(30));
        Assertions.assertThrows(EncryptorException.class, () -> checker.check(wrapper(null, System.currentTimeMillis())));
    }

    @Test
    public void test_concurrent_same_nonce_only_one_passes() throws Exception {
        InMemoryNonceChecker checker = new InMemoryNonceChecker(1000, Duration.ofSeconds(30));
        final int threads = 16;
        final long now = System.currentTimeMillis();
        final CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<Boolean>> futures = new ArrayList<>(threads);
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    try {
                        checker.check(wrapper("nonce-concurrent", now));
                        return Boolean.TRUE;
                    } catch (EncryptorException e) {
                        return Boolean.FALSE;
                    }
                }));
            }
            start.countDown();
            int passed = 0;
            for (Future<Boolean> future : futures) {
                if (Boolean.TRUE.equals(future.get(10, TimeUnit.SECONDS))) {
                    passed++;
                }
            }
            // 并发下同一个 nonce 只允许通过一次；"先查后写"的实现会放过多个
            Assertions.assertEquals(1, passed);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    public void test_capacity_overflow_does_not_break_check() {
        // 写入量远超容量上限时不能抛异常（淘汰是"先清过期、仍超限则按迭代顺序丢弃"）
        InMemoryNonceChecker checker = new InMemoryNonceChecker(4, Duration.ofSeconds(30));
        long now = System.currentTimeMillis();
        for (int i = 0; i < 50; i++) {
            checker.check(wrapper("nonce-" + i, now));
        }
    }

    @Test
    public void test_replay_within_capacity_rejected() {
        // 容量足够大（不发生淘汰）时，连续写入后的重放必须被拒
        InMemoryNonceChecker checker = new InMemoryNonceChecker(100, Duration.ofSeconds(30));
        long now = System.currentTimeMillis();
        for (int i = 0; i < 50; i++) {
            checker.check(wrapper("nonce-" + i, now));
        }
        Assertions.assertThrows(EncryptorException.class, () -> checker.check(wrapper("nonce-49", now)));
    }
}
