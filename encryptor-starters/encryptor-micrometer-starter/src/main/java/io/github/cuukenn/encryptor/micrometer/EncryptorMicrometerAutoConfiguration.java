package io.github.cuukenn.encryptor.micrometer;

import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.reactive.gateway.runtime.CryptoExecutor;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 可选的 Micrometer 指标自动装配（D1 + D3）：加解密计数/失败分类，以及网关密码学执行器的队列深度。
 *
 * <p><b>不需要 core 或任何 starter 改一行代码</b>：两个 starter 都是用
 * {@code ObjectProvider<EncryptorListener>} 取监听器并按 {@code @Order} 组合的，所以这里注册一个
 * {@link MicrometerEncryptorListener} bean 就会被自动接上，且不会挤掉用户自己的监听器；{@link CryptoExecutor}
 * 本身就是容器里的单例 bean（gateway starter 的 {@code @ConditionalOnMissingBean} 可被覆盖），这里只读它。</p>
 *
 * <p>本模块**不**依赖 actuator：只要容器里有 {@link MeterRegistry}（actuator 会提供，测试里可以用
 * {@code SimpleMeterRegistry}）就工作。放在 actuator 的 {@code MetricsAutoConfiguration} 之后，
 * 保证注册表已就绪；没有注册表时整块条件不满足、静默不装配。</p>
 *
 * <p>失败分类标签的基数由 {@link io.github.cuukenn.encryptor.exception.EncryptorFailure} 枚举决定，
 * 有界（当前 12 个值）；不合规分类归到 {@code INTERNAL}。</p>
 *
 * @author changgg
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(MeterRegistry.class)
// ⚠️ 排在网关自动装配之后：嵌套的 GatewayCryptoExecutorMetricsConfiguration 用
// @ConditionalOnBean(CryptoExecutor) 匹配 bean **定义**，若本类先于网关配置类求值，
// 条件恒不满足且无任何日志——D3 的 pending/rejected 指标会静默消失。
@AutoConfigureAfter(name = {
    "org.springframework.boot.actuate.autoconfigure.metrics.MetricsAutoConfiguration",
    "io.github.cuukenn.encryptor.reactive.gateway.configuration.GatewayEncryptorConfiguration"})
public class EncryptorMicrometerAutoConfiguration {

    /**
     * 监听器 bean：与用户自己定义的 {@link EncryptorListener} 并存；两侧 starter 会按
     * {@code @Order}/注册顺序把容器里的所有监听器组合进协议栈。
     */
    @Bean
    @ConditionalOnBean(MeterRegistry.class)
    public MicrometerEncryptorListener micrometerEncryptorListener(MeterRegistry registry) {
        return new MicrometerEncryptorListener(registry);
    }

    /** 网关侧（有 {@link CryptoExecutor} 才生效；servlet 应用里这段整体不装配）。 */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(CryptoExecutor.class)
    static class GatewayCryptoExecutorMetricsConfiguration {

        @Bean
        @ConditionalOnBean(CryptoExecutor.class)
        @ConditionalOnMissingBean(GatewayCryptoExecutorMetrics.class)
        public GatewayCryptoExecutorMetrics gatewayCryptoExecutorMetrics(MeterRegistry registry,
                                                                        CryptoExecutor executor) {
            return new GatewayCryptoExecutorMetrics(registry, executor);
        }
    }
}
