package io.github.cuukenn.encryptor.reactive.gateway.runtime;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link CryptoExecutor}：默认取值、待执行数记账（指标模块的数据来源）、被拒任务记账。
 *
 * @author changgg
 */
class CryptoExecutorTest {

    @Test
    void 默认实例取CPU核数与一千队列() {
        CryptoExecutor executor = CryptoExecutor.create();
        try {
            assertThat(executor.maxThreads()).isEqualTo(Runtime.getRuntime().availableProcessors());
            assertThat(executor.queueCapacity()).isEqualTo(CryptoExecutor.DEFAULT_QUEUE_CAPACITY);
            assertThat(executor.scheduler()).isNotNull();
            assertThat(executor.pendingTasks()).isZero();
            assertThat(executor.rejectedTasks()).isZero();
        } finally {
            executor.dispose();
        }
    }

    @Test
    void 待执行数含在跑与排队任务并在完成后回落() throws Exception {
        CryptoExecutor executor = new CryptoExecutor(1, 10);
        CountDownLatch running = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            // 占住唯一线程
            executor.scheduler().schedule(() -> {
                running.countDown();
                try {
                    release.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            assertThat(running.await(5, TimeUnit.SECONDS)).as("占位任务应开始执行").isTrue();
            assertThat(executor.pendingTasks()).as("1 个在跑").isEqualTo(1L);

            for (int i = 0; i < 4; i++) {
                executor.scheduler().schedule(() -> {
                    // no-op
                });
            }
            assertThat(executor.pendingTasks()).as("1 在跑 + 4 排队").isEqualTo(5L);

            release.countDown();
            assertThat(waitForPending(executor, 0L)).as("执行完后应回落到 0").isTrue();
        } finally {
            executor.dispose();
        }
    }

    @Test
    void 被拒任务记账且不计入待执行() {
        CryptoExecutor executor = CryptoExecutor.create();
        executor.dispose();
        // 已 dispose 的调度器必然拒收，正好用来钉死"被拒 → 记 rejected、不进 pending"
        assertThatThrownBy(() -> executor.scheduler().schedule(() -> {
            // no-op
        })).isInstanceOf(RejectedExecutionException.class);
        assertThat(executor.rejectedTasks()).isEqualTo(1L);
        assertThat(executor.pendingTasks()).isZero();
    }

    /** 完成是异步的，用轮询等待而非即时断言。 */
    private static boolean waitForPending(CryptoExecutor executor, long expected) throws InterruptedException {
        for (int i = 0; i < 200; i++) {
            if (executor.pendingTasks() == expected) {
                return true;
            }
            Thread.sleep(10L);
        }
        return false;
    }
}
