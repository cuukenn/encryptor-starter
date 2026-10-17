package io.github.cuukenn.encryptor.reactive.configuration;

import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * v2 协议的 reactive 侧自动装配回归测试（镜像 servlet 侧 EncryptorConfigBindingTest）。
 *
 * @author changgg
 */
class EncryptorReactiveAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(EncryptorReactiveAutoConfiguration.class));

    private static String[] rsaKeyProps(String kid) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            String priv = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
            String pub = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
            return new String[]{
                "encryptor.config.reactive.keys[0].kid=" + kid,
                "encryptor.config.reactive.keys[0].private-key=" + priv,
                "encryptor.config.reactive.keys[0].public-key=" + pub,
            };
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void 密钥绑定后产出DefaultProtocol与Runtime() {
        runner.withPropertyValues(rsaKeyProps("rk1"))
            .run(context -> {
                assertThat(context).hasSingleBean(DefaultProtocol.class);
                assertThat(context).hasSingleBean(EncryptorRuntime.class);
                DefaultProtocol protocol = context.getBean(DefaultProtocol.class);
                assertThat(protocol.keys().activeKid()).isEqualTo("rk1");
                assertThat(protocol.allowedAlgs()).containsExactly("RSA-OAEP-256");
            });
    }

    @Test
    void 没有密钥时启动失败() {
        runner.run(context -> {
            assertThat(context).hasFailed();
            Throwable t = context.getStartupFailure();
            while (t.getCause() != null) {
                t = t.getCause();
            }
            assertThat(t).hasMessageContaining("没有配置任何密钥");
        });
    }

    @Test
    void 默认值符合设计文档() {
        runner.withPropertyValues(rsaKeyProps("rk1"))
            .run(context -> {
                EncryptorConfig config = context.getBean(EncryptorConfig.class);
                assertThat(config.isRequireEncrypted()).isTrue();
                assertThat(config.getFailureStatus()).isEqualTo(400);
                assertThat(config.getMaxRequestSize()).isEqualTo(1048576L);
                assertThat(config.getMaxResponseSize()).isEqualTo(4194304L);
                assertThat(config.getDiscovery().isEnable()).isTrue();
                assertThat(config.getDiscovery().getPath()).isEqualTo("/.well-known/encryptor-keys");
                assertThat(config.getBypass().isRequest()).isFalse();
                assertThat(config.getBypass().isResponse()).isFalse();
            });
    }
}
