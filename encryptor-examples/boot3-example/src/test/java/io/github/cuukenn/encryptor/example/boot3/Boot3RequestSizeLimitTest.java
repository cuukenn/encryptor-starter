package io.github.cuukenn.encryptor.example.boot3;

import io.github.cuukenn.encryptor.example.boot3.Boot3ClientSupport.ActiveKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 风险点 2 的正向 gate（真实 Netty 请求链路）：请求体超过 max-request-size 必须 413
 * 且下游未进——共享 jar 口径下该路径先死于 getMethodValue，复制线上必须是完整行为：
 * {@code onErrorResume(DataBufferLimitException.class, e -> fail(exchange, 413))}
 * 在 Spring 6.x 的异常浮出点变化后仍按 413 收口（Task 2 §2 无法在共享 jar 上测出的边界）。
 *
 * <p>限宽上下文：max-request-size=2048（与默认上下文隔离，避免互相影响； RSA 封装的
 * JWE 信封自身约 1KB，小请求用例要限宽内、4096B 明文的用例必须限宽外）。</p>
 *
 * @author changgg
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "encryptor.config.reactive.max-request-size=2048")
class Boot3RequestSizeLimitTest {

    @LocalServerPort
    int port;

    @Autowired
    WebTestClient client;

    private static volatile Boot3ClientSupport.ActiveKey discovered;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        Boot3ClientSupport.registerDynamicProperties(registry);
    }

    private ActiveKey key() {
        if (discovered == null) {
            try {
                discovered = Boot3ClientSupport.fetchActiveKey(port);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
        return discovered;
    }

    @Test
    void 超限请求体必须413且不进下游() {
        Boot3ClientSupport.Sealed sealed = Boot3ClientSupport.seal(
            "{\"name\":\"" + "x".repeat(4096) + "\"}", "/api/limit", "POST", key());
        long before = DownstreamEchoServer.hits("/api/limit");
        client.post().uri("/api/limit")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{\"jwe\":\"" + sealed.compact + "\"}")
            .exchange()
            .expectStatus().isEqualTo(org.springframework.http.HttpStatus.PAYLOAD_TOO_LARGE)
            .expectHeader().exists("X-Encryptor-Trace");
        assertThat(DownstreamEchoServer.hits("/api/limit")).isEqualTo(before);
    }

    @Test
    void 限宽内的小请求正常往返() {
        Boot3ClientSupport.Sealed sealed = Boot3ClientSupport.seal("{\"m\":\"ok\"}", "/api/limit", "POST", key());
        client.post().uri("/api/limit")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{\"jwe\":\"" + sealed.compact + "\"}")
            .exchange()
            .expectStatus().isOk()
            .expectBody(String.class).value(payload -> {
                byte[] plain = Boot3ClientSupport.decryptResponse(payload, sealed.cek);
                assertThat(new String(plain, java.nio.charset.StandardCharsets.UTF_8))
                    .contains("\\\"m\\\":\\\"ok\\\""); // 下游 echo 把 body JSON 转义回显
            });
    }
}
