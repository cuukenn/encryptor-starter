package io.github.cuukenn.encryptor.audit;

import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import io.github.cuukenn.encryptor.jose.JweContext;

/**
 * 可观测性回调：解密成功/失败、封装失败。默认全部 no-op。
 *
 * <p>接线在 core（{@code JweCodec}），starter 不必改动即可把失败接进日志/指标：
 * 用 Spring 注册 {@code @Bean EncryptorListener} 即可；注册多个时由
 * {@link CompositeEncryptorListener} 按 {@code @Order}/注册顺序扇出。回调里不要打印密文/明文/密钥。
 *
 * @author changgg
 */
public interface EncryptorListener {

    /** 空实现：所有回调 no-op。 */
    EncryptorListener NONE = new EncryptorListener() {
    };

    /** 请求解密成功。 */
    default void onDecryptSuccess(JweContext context) {
        // no-op
    }

    /** 请求解密失败（含重放/过期/AAD/白名单/未知 kid 等一切失败分类）。 */
    default void onDecryptFailure(EncryptorFailure failure, Throwable cause) {
        // no-op
    }

    /** 响应封装失败。 */
    default void onEncryptFailure(EncryptorFailure failure, Throwable cause) {
        // no-op
    }
}
