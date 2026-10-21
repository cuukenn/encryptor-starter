package io.github.cuukenn.encryptor.configuration;

import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 多监听器接线：容器里注册多个 {@link EncryptorListener} bean 时，协议栈必须全部接上
 * （而不是按唯一 bean 解析导致启动失败）。
 *
 * @author changgg
 */
class EncryptorAutoConfigurationListenerTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(EncryptorAutoConfiguration.class));

    private static String[] rsaKeyProps(String kid) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            return new String[]{
                "encryptor.config.keys[0].kid=" + kid,
                "encryptor.config.keys[0].private-key="
                    + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                "encryptor.config.keys[0].public-key="
                    + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
            };
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void 多个监听器bean全部接上协议栈() {
        List<String> calls = new ArrayList<>();
        runner.withPropertyValues(rsaKeyProps("multi-1"))
            .withBean("listenerA", EncryptorListener.class, () -> recording("a", calls))
            .withBean("listenerB", EncryptorListener.class, () -> recording("b", calls))
            .run(context -> {
                assertThat(context).hasNotFailed();

                DefaultProtocol protocol = context.getBean(DefaultProtocol.class);
                assertThatThrownBy(() -> protocol.openRequest("not-a-jwe", "/x", "GET"))
                    .isInstanceOf(EncryptorException.class);

                assertThat(calls).containsExactlyInAnyOrder("a:decrypt-failure", "b:decrypt-failure");
            });
    }

    private static EncryptorListener recording(String name, List<String> calls) {
        return new EncryptorListener() {
            @Override
            public void onDecryptFailure(EncryptorFailure failure, Throwable cause) {
                calls.add(name + ":decrypt-failure");
            }
        };
    }
}
