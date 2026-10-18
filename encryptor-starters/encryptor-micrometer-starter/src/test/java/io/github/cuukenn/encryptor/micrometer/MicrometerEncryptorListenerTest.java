package io.github.cuukenn.encryptor.micrometer;

import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link MicrometerEncryptorListener}：成功/失败计数、失败分类覆盖率、空值归类。
 *
 * @author changgg
 */
class MicrometerEncryptorListenerTest {

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final EncryptorListener listener = new MicrometerEncryptorListener(registry);

    @Test
    void 解密成功与失败分别计数() {
        listener.onDecryptSuccess(null);
        listener.onDecryptSuccess(null);
        listener.onDecryptFailure(EncryptorFailure.REPLAY, new IllegalStateException("模拟"));

        assertThat(count("encryptor.decrypt", "result", "success")).isEqualTo(2.0);
        assertThat(count("encryptor.decrypt", "result", "failure")).isEqualTo(1.0);
        assertThat(count("encryptor.decrypt.failures", "failure", "REPLAY")).isEqualTo(1.0);
        assertThat(count("encryptor.decrypt.failures", "failure", "EXPIRED")).isZero();
    }

    @Test
    void 全部失败分类都预注册且空值归到INTERNAL() {
        for (EncryptorFailure failure : EncryptorFailure.values()) {
            assertThat(registry.find("encryptor.decrypt.failures").tag("failure", failure.name()).counter())
                .as("分类 %s 应已预注册", failure).isNotNull();
            assertThat(registry.find("encryptor.encrypt.failures").tag("failure", failure.name()).counter())
                .as("分类 %s 应已预注册", failure).isNotNull();
        }

        listener.onDecryptFailure(null, new IllegalStateException("模拟"));
        assertThat(count("encryptor.decrypt.failures", "failure", EncryptorFailure.INTERNAL.name())).isEqualTo(1.0);
    }

    @Test
    void 加密失败单独计数不影响解密() {
        listener.onEncryptFailure(EncryptorFailure.ENCRYPT_FAILED, new IllegalStateException("模拟"));

        assertThat(count("encryptor.encrypt.failures", "failure", "ENCRYPT_FAILED")).isEqualTo(1.0);
        assertThat(count("encryptor.encrypt.failures", "failure", EncryptorFailure.INTERNAL.name())).isZero();
        assertThat(count("encryptor.decrypt", "result", "failure")).isZero();
    }

    private double count(String name, String tag, String value) {
        return registry.get(name).tag(tag, value).counter().count();
    }
}
