package io.github.cuukenn.encryptor.reactive.config;

import io.github.cuukenn.encryptor.config.base.BypassConfigBase;

/**
 * 旁路开关（初始值；运行期经 {@code EncryptorRuntime.setBypass} 热改，无需重启）。
 *
 * <p>字段与默认值继承自 core 的 {@link BypassConfigBase}。</p>
 *
 * @author changgg
 */
public class BypassConfig extends BypassConfigBase {
}
