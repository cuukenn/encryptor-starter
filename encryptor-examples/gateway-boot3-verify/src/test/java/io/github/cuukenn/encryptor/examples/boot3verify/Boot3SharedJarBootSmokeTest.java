package io.github.cuukenn.encryptor.examples.boot3verify;

import io.github.cuukenn.encryptor.micrometer.MicrometerEncryptorListener;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.gateway.discovery.JwksEndpointFilter;
import io.github.cuukenn.encryptor.reactive.gateway.filter.EncryptorGatewayFilter;
import io.github.cuukenn.encryptor.reactive.gateway.filter.EncryptorResponseFilter;
import io.github.cuukenn.encryptor.reactive.gateway.runtime.CryptoExecutor;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import reactor.core.publisher.Flux;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 顺带厘清 Boot 3.5 装配面（不含请求处理）：三个共享 jar 的自动装配/bean 接线
 * 在 Boot 3.5 下全部成功——装配注册（AutoConfiguration.imports）、配置绑定、
 * objectProvider 监听器组合、路由 bean 都活着。
 *
 * <p>风险点 3（@AutoConfigureAfter 尊重与否）在这里有第一层实证：真 actuator
 * 自动配置在场（MetricsAutoConfiguration → SimpleMeterRegistry），若 Boot 3.5
 * 把 micrometer 自动配置排在它之前评估 @ConditionalOnBean(MeterRegistry)，
 * {@code micrometerEncryptorListener} 就不会装配、计数器也不会存在。</p>
 *
 * @author changgg
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class Boot3SharedJarBootSmokeTest {

    @Autowired
    ApplicationContext context;
    @Autowired
    io.micrometer.core.instrument.MeterRegistry registry;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        Boot3ClientSupport.registerDynamicProperties(registry);
    }

    @Test
    void 三个共享jar完成自动装配与bean接线() {
        // reactive 通用装配
        assertThat(context.getBean(DefaultProtocol.class)).isNotNull();
        assertThat(context.getBean(EncryptorRuntime.class)).isNotNull();
        // gateway 装配
        assertThat(context.getBean("encryptorGatewayFilter")).isInstanceOf(EncryptorGatewayFilter.class);
        assertThat(context.getBean("encryptorResponseFilter")).isInstanceOf(EncryptorResponseFilter.class);
        assertThat(context.getBean("gatewayJwksEndpointFilter")).isInstanceOf(JwksEndpointFilter.class);
        assertThat(context.getBean(CryptoExecutor.class)).isNotNull();
        // micrometer 装配（风险点 3 第一层证据：真 actuator 在场 → listener 在场）
        assertThat(context.containsBean("micrometerEncryptorListener")).isTrue();
        assertThat(context.getBean("micrometerEncryptorListener")).isInstanceOf(MicrometerEncryptorListener.class);
        // 监听器构造期把计数器一次注册齐（有将失败的分类计数也会在）
        assertThat(registry.find("encryptor.decrypt").tag("result", "success").counter()).isNotNull();
        assertThat(registry.find("encryptor.decrypt").tag("result", "failure").counter()).isNotNull();
        // 配置只保留前缀的三件套继承链在 Boot 3.5 绑定正常（gateway filter-config 深层 order 解析）
        assertThat(context.getBean(RouteLocator.class)).isNotNull();
        // 没有直接暴露路由数量 API：route locator 拉一次（动态配置的 downstream.base-uri 路由）
        assertThat(Flux.from(context.getBean(RouteLocator.class).getRoutes()).collectList().block()).isNotEmpty();
    }

    /**
     * 风险点 3 第二层证据：真实 Bean 3.5 上下文里，组合进协议栈的 micrometer 监听器
     * 被真实协议调用驱动：成功路径 success 计数递增、篡改路径 failure 计数递增。
     */
    @Test
    void 真实协议调用驱动micrometer计数递增() throws Exception {
        DefaultProtocol protocol = context.getBean(DefaultProtocol.class);
        Boot3ClientSupport.Sealed sealed = Boot3ClientSupport.seal("{\"c\":1}", "/api/counter", "POST");
        double before = countOf(registry, "encryptor.decrypt", "result", "success");
        protocol.openRequest(sealed.compact, "/api/counter", "POST");
        assertThat(countOf(registry, "encryptor.decrypt", "result", "success")).isGreaterThan(before);
        // 失败路径：改密文段（cek被封段）→ 解封失败
        Boot3ClientSupport.Sealed sealed2 = Boot3ClientSupport.seal("{\"c\":2}", "/api/counter", "POST");
        double beforeFailure = countOf(registry, "encryptor.decrypt", "result", "failure");
        try {
            protocol.openRequest(Boot3ClientSupport.tamper(sealed2.compact), "/api/counter", "POST");
        } catch (Exception expected) {
            // 解封失败按 EncryptorException 抛出（javax 线语义一致），计数仍要发生
        }
        assertThat(countOf(registry, "encryptor.decrypt", "result", "failure")).isGreaterThan(beforeFailure);
        // 失败分类计数器（tamper 命中 cek 段 → DECRYPT_FAILED）
        assertThat(registry.find("encryptor.decrypt.failures").counter()).isNotNull();
    }

    private static double countOf(io.micrometer.core.instrument.MeterRegistry meterRegistry,
                                  String name, String tagKey, String tagValue) {
        io.micrometer.core.instrument.Counter counter = meterRegistry.find(name).tag(tagKey, tagValue).counter();
        return counter == null ? 0 : counter.count();
    }
}
