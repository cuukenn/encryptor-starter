package io.github.cuukenn.encryptor.example.boot3;

import io.github.cuukenn.encryptor.example.boot3.Boot3ClientSupport.ActiveKey;
import io.github.cuukenn.encryptor.example.boot3.Boot3ClientSupport.Sealed;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * 响应链路的正向 gate：响应体超过 max-response-size 必须 500 不发明文
 * （{@code EncryptorResponseFilter} 在真实 Netty 写出路径上有界聚合 + 失败面开口，
 * 不能让明文漏出，也不能因限宽误伤常规响应——超限用例与正常往返共用一套契约）。
 *
 * <p>限宽上下文：max-response-size=1024，下游 /api/big 固定回 16KB+ 大响应。</p>
 *
 * @author changgg
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "encryptor.config.reactive.max-response-size=1024")
class Boot3ResponseSizeLimitTest {

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
    void 超限响应必须500不发明文() {
        Sealed sealed = Boot3ClientSupport.seal("n=big", "/api/big", "GET", key());
        client.get().uri("/api/big?jwe=" + java.net.URLEncoder.encode(sealed.compact,
                java.nio.charset.StandardCharsets.UTF_8))
            .exchange()
            .expectStatus().isEqualTo(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR)
            .expectHeader().exists("X-Encryptor-Trace")
            .expectBody().isEmpty(); // 500 响应无 body：明文既没原样漏出、也没封成 jwe
    }

    @Test
    void 限宽内的小响应正常往返() {
        Sealed sealed = Boot3ClientSupport.seal("{\"n\":\"small\"}", "/api/echo", "POST", key());
        client.post().uri("/api/echo")
            .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
            .bodyValue("{\"jwe\":\"" + sealed.compact + "\"}")
            .exchange()
            .expectStatus().isOk()
            .expectBody(String.class).value(payload -> {
                byte[] plain = Boot3ClientSupport.decryptResponse(payload, sealed.cek);
                org.assertj.core.api.Assertions.assertThat(new String(plain, java.nio.charset.StandardCharsets.UTF_8))
                    .contains("small");
            });
    }
}
