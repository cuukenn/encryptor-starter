package io.github.cuukenn.encryptor.reactive.gateway.config;

import io.github.cuukenn.encryptor.reactive.gateway.runtime.CryptoExecutor;

/**
 * 密码学有界执行器（{@link CryptoExecutor}）的容量配置（前缀
 * {@code encryptor.config.reactive.gateway.crypto-executor.*}）。
 *
 * <p>默认与 v2 引入时的取值一致：线程数 = CPU 核数（{@code threads=0} 表示自动），
 * 队列 1000。线程做的是 CPU 密集的 AEAD/非对称运算，超过核数无收益；队列用于吸收突发，
 * 满了回 503。需要整体自定义线程/队列策略时覆盖 {@code cryptoExecutor} bean。
 *
 * @author changgg
 */
public class CryptoExecutorConfig {

    /**
     * 执行器线程数；0 = CPU 核数（默认）。
     */
    private int threads = 0;

    /**
     * 队列容量（吸收突发；打满后请求侧回 503）。
     */
    private int queueCapacity = CryptoExecutor.DEFAULT_QUEUE_CAPACITY;

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    public int getQueueCapacity() {
        return queueCapacity;
    }

    public void setQueueCapacity(int queueCapacity) {
        this.queueCapacity = queueCapacity;
    }
}
