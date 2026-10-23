package io.github.cuukenn.encryptor.reactive.gateway.configuration;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.jose.KeyType;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Collections;

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
    void cryptoConfig引用未知kid时启动失败() throws Exception {
        GatewayEncryptorConfig config = new GatewayEncryptorConfig();
        config.getCryptoConfig().put("[/pay/.*]", Collections.singletonList("missing-kid"));

        assertThatThrownBy(() -> GatewayEncryptorConfiguration.validateCryptoKids(config, protocol()))
            .isInstanceOf(EncryptorException.class)
            .hasMessageContaining("missing-kid");
    }

    @Test
    void cryptoConfig引用已配置kid时通过() throws Exception {
        GatewayEncryptorConfig config = new GatewayEncryptorConfig();
        config.getCryptoConfig().put("[/pay/.*]", Collections.singletonList("k1"));

        assertThatCode(() -> GatewayEncryptorConfiguration.validateCryptoKids(config, protocol()))
            .doesNotThrowAnyException();
    }

    private static DefaultProtocol protocol() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return DefaultProtocol.builder()
            .key(new DefaultProtocol.KeyMaterial("k1", KeyType.RSA,
                Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())))
            .build();
    }

    @Test
    void failureStatus为已知状态码时通过() {
        assertThatCode(() -> GatewayEncryptorConfiguration.validateFailureStatus(400)).doesNotThrowAnyException();
        assertThatCode(() -> GatewayEncryptorConfiguration.validateFailureStatus(429)).doesNotThrowAnyException();
        assertThatCode(() -> GatewayEncryptorConfiguration.validateFailureStatus(503)).doesNotThrowAnyException();
    }
}
