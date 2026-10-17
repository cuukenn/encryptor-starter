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

/**
 * RSA 解封（JCE Cipher 每次新建）的并行扩展性：
 * 4 线程吞吐必须 ≥ 2.5× 单线程（防 v1 的"共享 Cipher 单锁串行"回归）。
 *
 * @author changgg
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 2, time = 1)
@Measurement(iterations = 3, time = 1)
@Fork(1)
@State(Scope.Benchmark)
public class RsaParallelBenchmark {

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
    public JweContext decryptSingleThread() {
        return codec.decryptRequest(compact, BenchSupport.URI, BenchSupport.METHOD);
    }

    @Benchmark
    @Threads(4)
    public JweContext decryptFourThreads() {
        return codec.decryptRequest(compact, BenchSupport.URI, BenchSupport.METHOD);
    }
}
