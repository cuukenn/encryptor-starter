package io.github.cuukenn.encryptor.bench;

import io.github.cuukenn.encryptor.jose.InMemoryNonceStore;
import io.github.cuukenn.encryptor.jose.ReplayGuard;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 防重放存储的隔离基准：{@code ReplayGuard.verify}（时间窗 + InMemoryNonceStore.consume 的
 * 分片锁 + CHM.compute + 摊还驱逐）。E2eBenchmark 复用同一 compact、无法携带 ReplayGuard
 * （第二次起 nonce 即重放），此前该每请求必经路径对阈值脚本全盲——本基准补上该盲区，
 * 量级参考：默认 10 万容量 / 10 分钟保留。
 *
 * @author changgg
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 2, time = 1)
@Measurement(iterations = 3, time = 1)
@Fork(1)
@State(Scope.Benchmark)
public class ReplayGuardBenchmark {

    private final AtomicLong sequence = new AtomicLong();

    private ReplayGuard guard;

    @Setup(Level.Trial)
    public void setup() {
        long ttl = 5 * 60 * 1000L;
        guard = new ReplayGuard(ttl, new InMemoryNonceStore(ttl * 2, 100_000));
    }

    @Benchmark
    @Threads(1)
    public void verifySingleThread() {
        guard.verify(System.currentTimeMillis(), "n-" + sequence.incrementAndGet());
    }

    @Benchmark
    @Threads(4)
    public void verifyFourThreads() {
        guard.verify(System.currentTimeMillis(), "n-" + sequence.incrementAndGet());
    }
}
