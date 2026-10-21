package io.github.cuukenn.encryptor.examples.boot3verify;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Boot 3.5 共享 jar 验证应用：SCG（spring-cloud-starter-gateway 2025.0.x）
 * + javax 代的三个 encryptor 共享候选（reactive/gateway/micrometer 1.0.0）。
 *
 * @author changgg
 */
@SpringBootApplication
public class Boot3GatewayVerifyApplication {

    public static ConfigurableApplicationContext run(String[] args) {
        // 独立运行时也起下游 echo：/api/** 全部转发到本机随机端口的普通应用（不带 encryptor）
        DownstreamEchoServer.start();
        System.setProperty("downstream.base-uri", DownstreamEchoServer.baseUri());
        return SpringApplication.run(Boot3GatewayVerifyApplication.class, args);
    }

    public static void main(String[] args) {
        run(args).close();
    }

    /**
     * 测试/独立运行时注入 {@code downstream.base-uri} 后，/api/** 转发到 JDK 下游 echo 服务。
     */
    @Bean
    RouteLocator downstreamRoute(RouteLocatorBuilder builder, Environment env) {
        String base = env.getProperty("downstream.base-uri");
        if (base == null || base.isBlank()) {
            return builder.routes().build();
        }
        return builder.routes()
            .route("downstream", r -> r.path("/api/**").uri(base))
            .build();
    }
}
