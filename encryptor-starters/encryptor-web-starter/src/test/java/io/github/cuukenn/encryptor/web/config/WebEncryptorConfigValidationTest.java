package io.github.cuukenn.encryptor.web.config;

import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * web 侧名单正则必须在配置初始化期编译，非法正则启动即失败，而不是等到第一个请求。
 *
 * @author changgg
 */
class WebEncryptorConfigValidationTest {

    @Test
    void 非法skipUri正则在初始化期失败() {
        WebEncryptorConfig config = new WebEncryptorConfig();
        config.getSkipUris().add("[");

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, config::afterPropertiesSet);
        assertTrue(error.getMessage().contains("skip-uris"));
    }

    @Test
    void 非法cryptoConfig正则在初始化期失败() {
        WebEncryptorConfig config = new WebEncryptorConfig();
        config.getCryptoConfig().put("[", Collections.singletonList("k1"));

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, config::afterPropertiesSet);
        assertTrue(error.getMessage().contains("crypto-config"));
    }
}
