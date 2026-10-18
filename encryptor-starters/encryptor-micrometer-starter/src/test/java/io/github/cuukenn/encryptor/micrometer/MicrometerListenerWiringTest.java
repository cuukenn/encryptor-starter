package io.github.cuukenn.encryptor.micrometer;

import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.configuration.EncryptorReactiveAutoConfiguration;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 端到端接线：本模块只注册一个 {@link EncryptorListener} bean，真实协议栈（reactive starter 的
 * 自动装配）必须自动接上它，并且真实解密失败要落到计数器上。
 *
 * <p>这条用例存在的意义：证明「加一个依赖就生效」不是文档承诺，而是容器里验证过的事实
 * （两个 starter 都是用 {@code ObjectProvider<EncryptorListener>} 取监听器，本模块不改它们一行代码）。</p>
 *
 * @author changgg
 */
class MicrometerListenerWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(EncryptorReactiveAutoConfiguration.class,
            EncryptorMicrometerAutoConfiguration.class));

    private static String[] rsaKeyProps(String kid) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            return new String[]{
                "encryptor.config.reactive.keys[0].kid=" + kid,
                "encryptor.config.reactive.keys[0].private-key="
                    + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                "encryptor.config.reactive.keys[0].public-key="
                    + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
            };
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void 真实协议栈接上监听器并记录解密失败() {
        runner.withPropertyValues(rsaKeyProps("meter-1"))
            .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
            .run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context.getBean(EncryptorListener.class)).isInstanceOf(MicrometerEncryptorListener.class);

                DefaultProtocol protocol = context.getBean(DefaultProtocol.class);
                assertThatThrownBy(() -> protocol.openRequest("not-a-jwe", "/bench", "GET"))
                    .isInstanceOf(EncryptorException.class);

                MeterRegistry registry = context.getBean(MeterRegistry.class);
                assertThat(registry.get("encryptor.decrypt").tag("result", "failure").counter().count())
                    .isEqualTo(1.0);
                assertThat(registry.get("encryptor.decrypt").tag("result", "success").counter().count()).isZero();
                assertThat(registry.find("encryptor.decrypt.failures").counters().stream()
                    .filter(counter -> counter.count() > 0).count())
                    .as("应恰好有一个失败分类被计数")
                    .isEqualTo(1L);
            });
    }
}
