package io.github.cuukenn.encryptor.bench;

import io.github.cuukenn.encryptor.jose.EcCipherSuite;
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
 * ECDH-ES（P-256 直接密钥协商）与服务端解封路径：与 {@link E2eBenchmark} 同构，便于直接对比
 * "RSA 私钥运算"与"ECDH + Concat KDF"两条 CEK 获取路径的成本。
 *
 * <p>方法名带 {@code ecdh} 前缀，避免与 {@link RsaParallelBenchmark} 的同名方法混淆
 * （{@code check-thresholds.sh} 按全名精确取数）。</p>
 *
 * @author changgg
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 2, time = 1)
@Measurement(iterations = 3, time = 1)
@Fork(1)
@State(Scope.Benchmark)
public class EcdhEsBenchmark {

    private final AtomicLong sequence = new AtomicLong();

    private JweCodec codec;
    private String compact;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        ServerKeyStore keys = BenchSupport.ecStore();
        // 显式白名单：EcCipherSuite 不接受协议默认的 RSA-OAEP-256（构造期即 fail-fast）
        codec = new JweCodec(keys, Collections.singletonList(new EcCipherSuite()),
            Collections.singleton(EcCipherSuite.ALG), Collections.singleton(JweCodec.DEFAULT_ENC));
        compact = BenchSupport.sealEcdh(keys);
    }

    /** 与 {@link E2eBenchmark#roundTrip()} 同构：解请求 + 加响应。 */
    @Benchmark
    @Threads(1)
    public String ecdhRoundTrip() {
        JweContext context = codec.decryptRequest(compact, BenchSupport.URI, BenchSupport.METHOD);
        return codec.encryptResponse(context.plaintext(), context.cek(), BenchSupport.URI, BenchSupport.METHOD,
            System.currentTimeMillis(), "n-" + sequence.incrementAndGet());
    }

    @Benchmark
    @Threads(1)
    public JweContext ecdhDecryptSingleThread() {
        return codec.decryptRequest(compact, BenchSupport.URI, BenchSupport.METHOD);
    }

    @Benchmark
    @Threads(4)
    public JweContext ecdhDecryptFourThreads() {
        return codec.decryptRequest(compact, BenchSupport.URI, BenchSupport.METHOD);
    }
}
