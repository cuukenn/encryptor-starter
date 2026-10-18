package io.github.cuukenn.encryptor.micrometer;

import io.github.cuukenn.encryptor.reactive.gateway.runtime.CryptoExecutor;
import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * 网关密码学执行器的指标（D3）。
 *
 * <p>Reactor 自己的 {@code Scannable.Attr.BUFFERED} 读不到真实积压（任务被派进执行器内部队列后就不可见），
 * 所以 {@link CryptoExecutor} 精确记账，这里只做导出：</p>
 * <ul>
 *   <li>{@code encryptor.gateway.crypto.pending} —— 在跑 + 排队（提交 − 完成），过载第一信号
 *       （持续 &gt; {@code threads} 即在排队）；</li>
 *   <li>{@code encryptor.gateway.crypto.rejected} —— 因队列满被拒总数（每个都对应一次 503）；</li>
 *   <li>{@code encryptor.gateway.crypto.threads} / {@code ...queue.capacity} —— 静态配置值，
 *       让看板能判断"排队深度相对容量"。</li>
 * </ul>
 *
 * <p>持有 {@link CryptoExecutor} 强引用：Micrometer 的 Gauge 只弱引用被观察对象，
 * 这里保证它不会被 GC（生产的执行器是单例 bean，同样不会）。</p>
 *
 * @author changgg
 */
public class GatewayCryptoExecutorMetrics {

    public static final String PENDING = "encryptor.gateway.crypto.pending";
    public static final String REJECTED = "encryptor.gateway.crypto.rejected";
    public static final String THREADS = "encryptor.gateway.crypto.threads";
    public static final String QUEUE_CAPACITY = "encryptor.gateway.crypto.queue.capacity";

    private final CryptoExecutor executor;

    public GatewayCryptoExecutorMetrics(MeterRegistry registry, CryptoExecutor executor) {
        this.executor = executor;
        Gauge.builder(PENDING, executor, CryptoExecutor::pendingTasks)
            .description("密码学任务在跑 + 排队数（提交 − 完成）")
            .register(registry);
        Gauge.builder(THREADS, executor, value -> value.maxThreads())
            .description("密码学执行器线程数（= CPU 核数）")
            .register(registry);
        Gauge.builder(QUEUE_CAPACITY, executor, value -> value.queueCapacity())
            .description("密码学执行器队列容量")
            .register(registry);
        FunctionCounter.builder(REJECTED, executor, CryptoExecutor::rejectedTasks)
            .description("因队列满被拒的密码学任务总数（每个对应一次 503）")
            .register(registry);
    }

    /** 被观察的执行器（同时是强引用）。 */
    public CryptoExecutor executor() {
        return executor;
    }
}
