package io.github.cuukenn.encryptor.reactive.gateway.runtime;

import org.springframework.beans.factory.DisposableBean;
import reactor.core.Disposable;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * 网关密码学有界执行器：请求解密与响应加密共用的一个 {@code boundedElastic} 调度器，外加一层计数。
 *
 * <p>为什么要有界：解密/加密是阻塞式 JCA 调用，不能占着事件循环线程；队列满时 {@code schedule}
 * 抛 {@link RejectedExecutionException}，请求侧据此回 <b>503</b>（服务端过载，不能把 503 伪装成
 * 客户端 4xx），相应次数记在 {@link #rejectedTasks()}。</p>
 *
 * <p>为什么外面还要包一层计数：过载时最先要看的信号是"有多少密码学任务在跑/在等"，而 Reactor 的
 * {@code Scannable.Attr.BUFFERED}（{@code estimateSize()}）只反映它自己的待派发队列——任务一旦被
 * 派进执行器内部队列就看不到了，实测恒为 0。故这里用「提交数 − 完成数」精确记账，
 * 供指标模块（{@code encryptor-micrometer-spring-boot-starter}）读取。</p>
 *
 * <p>取值与 v2 引入时一致：线程数 = CPU 核数，队列 1000。线程做的是 CPU 密集的 AEAD/非对称运算，
 * 超过核数无收益；队列用于吸收突发。</p>
 *
 * @author changgg
 */
public class CryptoExecutor implements DisposableBean {

    /** 调度器名（同时是线程名前缀）。 */
    public static final String SCHEDULER_NAME = "encryptor-crypto";

    /** 默认队列容量：与 v2 引入时的取值一致（纯过载参数，与协议无关）。 */
    public static final int DEFAULT_QUEUE_CAPACITY = 1000;

    private final int maxThreads;
    private final int queueCapacity;
    private final CountingScheduler scheduler;
    private final AtomicLong submitted = new AtomicLong();
    private final AtomicLong completed = new AtomicLong();
    private final AtomicLong rejected = new AtomicLong();

    public CryptoExecutor(int maxThreads, int queueCapacity) {
        if (maxThreads <= 0) {
            throw new IllegalArgumentException("maxThreads 必须为正: " + maxThreads);
        }
        if (queueCapacity <= 0) {
            throw new IllegalArgumentException("queueCapacity 必须为正: " + queueCapacity);
        }
        this.maxThreads = maxThreads;
        this.queueCapacity = queueCapacity;
        this.scheduler = new CountingScheduler(Schedulers.newBoundedElastic(maxThreads, queueCapacity, SCHEDULER_NAME));
    }

    /** 默认实例：CPU 核数线程 + {@value #DEFAULT_QUEUE_CAPACITY} 队列。 */
    public static CryptoExecutor create() {
        return new CryptoExecutor(Runtime.getRuntime().availableProcessors(), DEFAULT_QUEUE_CAPACITY);
    }

    /** 供 {@code subscribeOn(...)} 使用的（带计数的）调度器。 */
    public Scheduler scheduler() {
        return scheduler;
    }

    public int maxThreads() {
        return maxThreads;
    }

    public int queueCapacity() {
        return queueCapacity;
    }

    /** 已提交未完成的任务数 = 正在执行 + 排队等待（过载的第一手信号）。 */
    public long pendingTasks() {
        return submitted.get() - completed.get();
    }

    /** 累计因队列满被拒的任务数（每一个都会变成一次 503）。 */
    public long rejectedTasks() {
        return rejected.get();
    }

    /** 释放线程池（测试/关闭用；生产由容器在关闭时调用）。 */
    public void dispose() {
        scheduler.dispose();
    }

    /** Spring 容器关闭回调：{@code boundedElastic} 的线程是非守护线程，必须显式释放。 */
    @Override
    public void destroy() {
        dispose();
    }

    /** 成功提交则计数；被拒只记 {@link #rejected} 并原样抛出（不能算作"在跑"）。 */
    private Disposable submit(Supplier<Disposable> action) {
        try {
            Disposable disposable = action.get();
            submitted.incrementAndGet();
            return disposable;
        } catch (RejectedExecutionException e) {
            rejected.incrementAndGet();
            throw e;
        }
    }

    /** 任务结束时记账（异常也要记，否则 pending 会永久泄漏）。 */
    private Runnable count(Runnable task) {
        return () -> {
            try {
                task.run();
            } finally {
                completed.incrementAndGet();
            }
        };
    }

    @Override
    public String toString() {
        return "CryptoExecutor{threads=" + maxThreads + ", queue=" + queueCapacity
            + ", pending=" + pendingTasks() + "}";
    }

    /** 记账 + 转发的 {@link Scheduler} 包装；周期任务永不"完成"，故只转发不记账。 */
    private final class CountingScheduler implements Scheduler {

        private final Scheduler delegate;

        private CountingScheduler(Scheduler delegate) {
            this.delegate = delegate;
        }

        @Override
        public Disposable schedule(Runnable task) {
            return submit(() -> delegate.schedule(count(task)));
        }

        @Override
        public Disposable schedule(Runnable task, long delay, TimeUnit unit) {
            return submit(() -> delegate.schedule(count(task), delay, unit));
        }

        @Override
        public Disposable schedulePeriodically(Runnable task, long initialDelay, long period, TimeUnit unit) {
            return delegate.schedulePeriodically(task, initialDelay, period, unit);
        }

        @Override
        public Worker createWorker() {
            return new CountingWorker(delegate.createWorker());
        }

        @Override
        public long now(TimeUnit unit) {
            return delegate.now(unit);
        }

        @Override
        public void start() {
            delegate.start();
        }

        @Override
        public void dispose() {
            delegate.dispose();
        }

        @Override
        public boolean isDisposed() {
            return delegate.isDisposed();
        }

        @Override
        public String toString() {
            return delegate.toString();
        }
    }

    /** Worker 版本：同样只记账 + 转发（{@code subscribeOn} 不走 worker，保留完整性以对齐 SPI）。 */
    private final class CountingWorker implements Scheduler.Worker {

        private final Scheduler.Worker delegate;

        private CountingWorker(Scheduler.Worker delegate) {
            this.delegate = delegate;
        }

        @Override
        public Disposable schedule(Runnable task) {
            return submit(() -> delegate.schedule(count(task)));
        }

        @Override
        public Disposable schedule(Runnable task, long delay, TimeUnit unit) {
            return submit(() -> delegate.schedule(count(task), delay, unit));
        }

        @Override
        public Disposable schedulePeriodically(Runnable task, long initialDelay, long period, TimeUnit unit) {
            return delegate.schedulePeriodically(task, initialDelay, period, unit);
        }

        @Override
        public void dispose() {
            delegate.dispose();
        }

        @Override
        public boolean isDisposed() {
            return delegate.isDisposed();
        }
    }
}
