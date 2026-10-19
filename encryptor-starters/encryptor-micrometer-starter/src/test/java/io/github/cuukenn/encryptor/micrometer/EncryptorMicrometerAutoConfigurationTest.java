package io.github.cuukenn.encryptor.micrometer;

import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.reactive.gateway.runtime.CryptoExecutor;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 自动装配条件：有注册表才装、用户自己的监听器优先、有网关执行器才导出队列深度指标。
 *
 * @author changgg
 */
class EncryptorMicrometerAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(EncryptorMicrometerAutoConfiguration.class));

    @Test
    void 有注册表时注册监听器bean() {
        runner.withBean(MeterRegistry.class, SimpleMeterRegistry::new).run(context -> {
            assertThat(context).hasSingleBean(MicrometerEncryptorListener.class);
            assertThat(context.getBean(EncryptorListener.class)).isInstanceOf(MicrometerEncryptorListener.class);
            assertThat(context).doesNotHaveBean(GatewayCryptoExecutorMetrics.class);
        });
    }

    @Test
    void 没有注册表时整块不装配() {
        runner.run(context -> assertThat(context).doesNotHaveBean(MicrometerEncryptorListener.class));
    }

    @Test
    void 用户监听器与指标监听器并存() {
        runner.withBean(MeterRegistry.class, SimpleMeterRegistry::new)
            .withBean("userListener", EncryptorListener.class, () -> new EncryptorListener() {
            })
            .run(context -> {
                assertThat(context).hasSingleBean(MicrometerEncryptorListener.class);
                assertThat(context.getBeansOfType(EncryptorListener.class)).hasSize(2);
                assertThat(context.getBeansOfType(EncryptorListener.class).values())
                    .anyMatch(listener -> listener instanceof MicrometerEncryptorListener);
            });
    }

    @Test
    void 有网关执行器时导出队列深度指标() {
        runner.withBean(MeterRegistry.class, SimpleMeterRegistry::new)
            .withBean(CryptoExecutor.class, CryptoExecutor::create)
            .run(context -> {
                CryptoExecutor executor = context.getBean(CryptoExecutor.class);
                try {
                    assertThat(context).hasSingleBean(GatewayCryptoExecutorMetrics.class);
                    MeterRegistry registry = context.getBean(MeterRegistry.class);
                    assertThat(registry.find(GatewayCryptoExecutorMetrics.PENDING).gauge()).isNotNull();
                    assertThat(registry.find(GatewayCryptoExecutorMetrics.REJECTED).functionCounter()).isNotNull();
                    assertThat(registry.find(GatewayCryptoExecutorMetrics.PENDING).gauge().value()).isZero();
                    assertThat(registry.find(GatewayCryptoExecutorMetrics.THREADS).gauge().value())
                        .isEqualTo(executor.maxThreads());
                } finally {
                    executor.dispose();
                }
            });
    }
}
