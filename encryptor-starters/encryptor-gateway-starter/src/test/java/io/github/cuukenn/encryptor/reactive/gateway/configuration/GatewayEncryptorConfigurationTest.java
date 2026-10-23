package io.github.cuukenn.encryptor.reactive.gateway.configuration;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 网关失败面的启动期校验：{@code failure-status} 最终由 {@code HttpStatus.valueOf(int)} 映射，
 * Spring 枚举里没有的码（如 499）必须在启动期拦住，否则每次失败都会再抛 IAE 变成 500。
 *
 * @author changgg
 */
class GatewayEncryptorConfigurationTest {

    @Test
    void failureStatus必须是Spring已知状态码() {
        assertThatThrownBy(() -> GatewayEncryptorConfiguration.validateFailureStatus(499))
            .isInstanceOf(EncryptorException.class)
            .hasMessageContaining("failure-status")
            .hasMessageContaining("499");
    }

    @Test
    void failureStatus为已知状态码时通过() {
        assertThatCode(() -> GatewayEncryptorConfiguration.validateFailureStatus(400)).doesNotThrowAnyException();
        assertThatCode(() -> GatewayEncryptorConfiguration.validateFailureStatus(429)).doesNotThrowAnyException();
        assertThatCode(() -> GatewayEncryptorConfiguration.validateFailureStatus(503)).doesNotThrowAnyException();
    }
}
