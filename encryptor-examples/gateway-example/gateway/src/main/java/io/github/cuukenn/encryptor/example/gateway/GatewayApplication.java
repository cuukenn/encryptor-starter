package io.github.cuukenn.encryptor.example.gateway;

import io.github.cuukenn.encryptor.core.CheckerStrategy;
import io.github.cuukenn.encryptor.core.checker.InMemoryNonceChecker;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.time.Duration;

/**
 * @author changgg
 */
@SpringBootApplication
public class GatewayApplication {
    @Bean
    public CheckerStrategy nonceChecker() {
        return new InMemoryNonceChecker(1000, Duration.ofSeconds(30));
    }

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
