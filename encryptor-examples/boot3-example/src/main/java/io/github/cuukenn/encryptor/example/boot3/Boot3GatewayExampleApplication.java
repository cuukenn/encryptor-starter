package io.github.cuukenn.encryptor.example.boot3;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Boot 3.5 网关示例应用：SCG（spring-cloud-starter-gateway 2025.0.x）
 * + encryptor-gateway-boot3-starter（复制线 3.0.0，JDK 17 编译）
 * + encryptor-micrometer-spring-boot-starter（共享线 1.0.0）。
 *
 * <p>独立运行（{@code mvn -Pboot3 -pl encryptor-examples/boot3-example spring-boot:run} 或
 * {@code java -jar target/boot3-gateway-example.jar}）时会在 127.0.0.1 随机端口起一个
 * 普通（不带 encryptor）回显下游并把 {@code downstream.base-uri} 注入路由 bean；
 * 演示密钥与 JWKS 发现端点来自 application.yml（RSA gw-2026 + EC ec-gw-2026）。
 * 之后可跑 {@code node front/test.js} 做端到端断言（生命周期与 javax 网关示例一致）；
 * 也可以改为复用 javax 线 {@code encryptor-examples/gateway-example/web}（端口 8082 的
 * 非 encryptor 普通 web 应用）当真实下游（README 说明）。</p>
 *
 * @author changgg
 */
@SpringBootApplication
public class Boot3GatewayExampleApplication {

    public static ConfigurableApplicationContext run(String[] args) {
        DownstreamEchoServer.start();
        System.setProperty("downstream.base-uri", DownstreamEchoServer.baseUri());
        return SpringApplication.run(Boot3GatewayExampleApplication.class, args);
    }    public static void main(String[] args) {
        // 独立运行：起普通回显下游 + 注 downstream.base-uri（网关解密后转发明文给它），启动后常驻
        run(args);
    }

    /**
     * 测试/独立运行时注入 {@code downstream.base-uri} 后，/api/**、/test/** 转发到普通下游
     * （不带 encryptor；网关解密后转发明文，密钥由 encryptor 线掌管）。
     */
    @Bean
    RouteLocator downstreamRoute(RouteLocatorBuilder builder, Environment env) {
        String base = env.getProperty("downstream.base-uri");
        if (base == null || base.isBlank()) {
            return builder.routes().build();
        }
        return builder.routes()
            .route("downstream-api", r -> r.path("/api/**").uri(base))
            .route("downstream-test", r -> r.path("/test/**").uri(base))
            .build();
    }
}
