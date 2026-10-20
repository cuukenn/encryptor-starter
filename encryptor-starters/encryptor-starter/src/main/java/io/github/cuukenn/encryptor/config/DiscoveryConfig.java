package io.github.cuukenn.encryptor.config;

import io.github.cuukenn.encryptor.config.base.DiscoveryConfigBase;

/**
 * JWKS 只读发现端点配置（客户端按 kid 取公钥，浏览器无法按需重发 ⇒ 没有它就无法平滑轮换）。
 *
 * <p>字段与默认值继承自 core 的 {@link DiscoveryConfigBase}。</p>
 *
 * @author changgg
 */
public class DiscoveryConfig extends DiscoveryConfigBase {
}
