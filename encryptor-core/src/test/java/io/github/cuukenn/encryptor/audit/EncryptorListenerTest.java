package io.github.cuukenn.encryptor.audit;

import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * {@link EncryptorListener} 契约测试：默认方法必须全部 no-op（不接任何实现也能安全调用）。
 *
 * @author changgg
 */
class EncryptorListenerTest {

    @Test
    void 默认实现全部为noop且不惧null参数() {
        EncryptorListener listener = new EncryptorListener() {
        };

        assertDoesNotThrow(() -> listener.onDecryptSuccess(null));
        assertDoesNotThrow(() -> listener.onDecryptFailure(EncryptorFailure.UNKNOWN_KID, null));
        assertDoesNotThrow(() -> listener.onDecryptFailure(null, null));
        assertDoesNotThrow(() -> listener.onEncryptFailure(EncryptorFailure.ENCRYPT_FAILED, null));
        assertDoesNotThrow(() -> listener.onEncryptFailure(null, null));
    }
}
