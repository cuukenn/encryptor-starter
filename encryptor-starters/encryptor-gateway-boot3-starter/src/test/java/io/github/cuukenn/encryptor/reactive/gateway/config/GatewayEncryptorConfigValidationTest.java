package io.github.cuukenn.encryptor.reactive.gateway.config;

import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 网关侧名单正则必须在配置初始化期编译（与 servlet 侧成对）。
 *
 * @author changgg
 */
class GatewayEncryptorConfigValidationTest {

    @Test
    void 非法skipUri正则在初始化期失败() {
        GatewayEncryptorConfig config = new GatewayEncryptorConfig();
        config.getSkipUris().add("[");

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, config::afterPropertiesSet);
        assertTrue(error.getMessage().contains("skip-uris"));
    }

    @Test
    void 非法cryptoConfig正则在初始化期失败() {
        GatewayEncryptorConfig config = new GatewayEncryptorConfig();
        config.getCryptoConfig().put("[", Collections.singletonList("k1"));

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, config::afterPropertiesSet);
        assertTrue(error.getMessage().contains("crypto-config"));
    }
}
