package io.github.cuukenn.encryptor.bench;

import io.github.cuukenn.encryptor.jose.JceCipherSuite;
import io.github.cuukenn.encryptor.jose.JweCodec;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.jose.ServerKeyStore;
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

import java.util.Collections;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 一次完整往返（解请求 + 加响应）的吞吐与分配（bytes/op 由 {@code -prof gc} 的
 * {@code gc.alloc.rate.norm} 采集，check-thresholds.sh 与基线比对，超基线 +10% 即失败）。
 *
 * @author changgg
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 2, time = 1)
@Measurement(iterations = 3, time = 1)
@Fork(1)
@State(Scope.Benchmark)
public class E2eBenchmark {

    private final AtomicLong sequence = new AtomicLong();

    private JweCodec codec;
    private String compact;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        ServerKeyStore keys = BenchSupport.rsaStore();
        codec = new JweCodec(keys, Collections.singletonList(new JceCipherSuite()),
            Collections.<String>emptySet(), Collections.<String>emptySet());
        compact = BenchSupport.seal(keys);
    }

    @Benchmark
    @Threads(1)
    public String roundTrip() {
        JweContext context = codec.decryptRequest(compact, BenchSupport.URI, BenchSupport.METHOD);
        return codec.encryptResponse(context.plaintext(), context.cek(), BenchSupport.URI, BenchSupport.METHOD,
            System.currentTimeMillis(), "n-" + sequence.incrementAndGet());
    }
}
