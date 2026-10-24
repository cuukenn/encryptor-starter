package io.github.cuukenn.encryptor.micrometer;

import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

import java.util.EnumMap;

/**
 * 把 core 的 {@link EncryptorListener} 回调翻译成 Micrometer 计数器（D1）。
 *
 * <p>指标（前缀 {@code encryptor.}）：</p>
 * <ul>
 *   <li>{@code encryptor.decrypt}{@code result=success|failure} —— 请求解密总次数；</li>
 *   <li>{@code encryptor.encrypt}{@code result=success|failure} —— 响应加密总次数；</li>
 *   <li>{@code encryptor.decrypt.failures}{@code failure=<枚举名>} —— 按失败分类计数；</li>
 *   <li>{@code encryptor.encrypt.failures}{@code failure=<枚举名>} —— 响应加密失败（同一分类口径）。</li>
 * </ul>
 *
 * <p>tag 值就是 {@link EncryptorFailure} 的枚举名，所以 core 新增分类会自动出现、不会漏报；
 * 标签基数有界（枚举 + 两个 result）。{@code null} 或未知分类归到 {@code INTERNAL}。</p>
 *
 * <p><b>为什么不记耗时</b>：{@code EncryptorListener} 的三个回调里没有耗时段，加时间要改 core 热路径
 * （收益不明）。要看延迟请结合应用自身的 HTTP 指标与网关执行器的队列深度指标。</p>
 *
 * <p>计数器在构造期一次性注册（含全部失败分类），回调里只做一次 {@code EnumMap} 查表 + {@code increment()}，
 * 不在热路径上做字符串拼接或注册。</p>
 *
 * @author changgg
 */
public class MicrometerEncryptorListener implements EncryptorListener {

    private static final String DECRYPT = "encryptor.decrypt";
    private static final String ENCRYPT = "encryptor.encrypt";
    private static final String DECRYPT_FAILURES = "encryptor.decrypt.failures";
    private static final String ENCRYPT_FAILURES = "encryptor.encrypt.failures";
    private static final String TAG_RESULT = "result";
    private static final String TAG_FAILURE = "failure";
    private static final String SUCCESS = "success";
    private static final String FAILURE = "failure";

    private final Counter decryptSuccess;
    private final Counter decryptFailure;
    private final Counter encryptSuccess;
    private final EnumMap<EncryptorFailure, Counter> decryptFailures = new EnumMap<>(EncryptorFailure.class);
    private final EnumMap<EncryptorFailure, Counter> encryptFailures = new EnumMap<>(EncryptorFailure.class);

    public MicrometerEncryptorListener(MeterRegistry registry) {
        this.decryptSuccess = Counter.builder(DECRYPT)
            .tag(TAG_RESULT, SUCCESS)
            .description("请求解密成功次数")
            .register(registry);
        this.decryptFailure = Counter.builder(DECRYPT)
            .tag(TAG_RESULT, FAILURE)
            .description("请求解密失败次数")
            .register(registry);
        this.encryptSuccess = Counter.builder(ENCRYPT)
            .tag(TAG_RESULT, SUCCESS)
            .description("响应加密成功次数")
            .register(registry);
        for (EncryptorFailure failure : EncryptorFailure.values()) {
            decryptFailures.put(failure, failureCounter(registry, DECRYPT_FAILURES, failure));
            encryptFailures.put(failure, failureCounter(registry, ENCRYPT_FAILURES, failure));
        }
    }

    @Override
    public void onDecryptSuccess(JweContext context) {
        decryptSuccess.increment();
    }

    @Override
    public void onDecryptFailure(EncryptorFailure failure, Throwable error) {
        decryptFailure.increment();
        counter(decryptFailures, failure).increment();
    }

    @Override
    public void onEncryptSuccess() {
        encryptSuccess.increment();
    }

    @Override
    public void onEncryptFailure(EncryptorFailure failure, Throwable error) {
        counter(encryptFailures, failure).increment();
    }

    /** 未知/空分类归到 {@code INTERNAL}：宁可少一个分类，也不能因为空值丢掉一次失败。 */
    private static Counter counter(EnumMap<EncryptorFailure, Counter> counters, EncryptorFailure failure) {
        Counter counter = failure == null ? null : counters.get(failure);
        return counter == null ? counters.get(EncryptorFailure.INTERNAL) : counter;
    }

    private static Counter failureCounter(MeterRegistry registry, String name, EncryptorFailure failure) {
        return Counter.builder(name)
            .tag(TAG_FAILURE, failure.name())
            .description("加解密失败分类计数")
            .register(registry);
    }
}
