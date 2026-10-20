package io.github.cuukenn.encryptor.reactive.config;

import io.github.cuukenn.encryptor.config.base.EncryptorConfigBase;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * v2 协议配置（reactive 侧，前缀 {@code encryptor.config.reactive}）。
 *
 * <p>字段、默认值与 getter/setter 继承自 core 的 {@link EncryptorConfigBase}；
 * 本类只负责 reactive 侧的配置前缀，避免与 servlet 侧双写漂移。</p>
 *
 * @author changgg
 */
@ConfigurationProperties(prefix = EncryptorConfig.PREFIX)
public class EncryptorConfig extends EncryptorConfigBase<KeyMaterialConfig, BypassConfig, DiscoveryConfig> {
    public static final String PREFIX = "encryptor.config.reactive";

    public EncryptorConfig() {
        super(new BypassConfig(), new DiscoveryConfig());
    }
}
