package io.github.cuukenn.encryptor.example.boot3;

import io.github.cuukenn.encryptor.example.boot3.Boot3ClientSupport.ActiveKey;
import io.github.cuukenn.encryptor.example.boot3.Boot3ClientSupport.Sealed;
import io.github.cuukenn.encryptor.micrometer.MicrometerEncryptorListener;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.http.HttpStatus;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.boot.test.web.server.LocalServerPort;
import reactor.core.publisher.Flux;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * boot3 复制线端到端正向行为 gate（真实 Netty 链路 + 普通回显下游）。
 *
 * <p>这是风险点 1（SCG ordering）/风险点 2（413 上限）的<b>正向</b>断言：共享 jar 在
 * Spring 6.2 上任何请求都无法处理（NoSuchMethodError，Task 2 失败边界证据）；复制线
 * {@code encryptor-gateway-boot3-starter 3.0.0} 必须不但"不炸"，还要让
 * 请求解密 → 下游转发 → 响应回加密 → 客户端 dir 解回的<b>全链路正向语义</b>
 * 在 SCG 2025.0 的真实过滤器排序下成立。安全语义（三载体/篡改/重放/未知 kid/发现端点）
 * 与 javax 线网关用同一断言口径；密钥经 JWKS 发现端点取演示密钥（与 node 前端同路径）。</p>
 *
 * @author changgg
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class Boot3GatewayEndToEndTest {

    @LocalServerPort
    int port;

    @Autowired
    ApplicationContext context;
    @Autowired
    WebTestClient client;
    @Autowired
    io.micrometer.core.instrument.MeterRegistry meterRegistry;
    @Autowired
    RouteLocator routeLocator;

    private static volatile ActiveKey discovered;

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

    /** 重新发现（未知 kid 用例需要换 kid 仍打本网关）。 */
    private ActiveKey rekey(String kid) {
        ActiveKey known = key();
        return new ActiveKey(kid, known.publicKey);
    }

    @Test
    void jwks发现端点与ETag() {
        EtagProbe probe = probeEtag();
        assertThat(probe.body).contains("activeKid").contains("\"n\"");
        // If-None-Match 命中 → 304（无 body）
        client.get().uri("/.well-known/encryptor-keys")
            .header("If-None-Match", probe.etag)
            .exchange()
            .expectStatus().isEqualTo(HttpStatus.NOT_MODIFIED);
        // 未命中 → 200
        client.get().uri("/.well-known/encryptor-keys")
            .header("If-None-Match", "\"bogus\"")
            .exchange()
            .expectStatus().isOk()
            .expectBody(String.class).value(body -> assertThat(body).isEqualTo(probe.body));
    }

    private EtagProbe probeEtag() {
        org.springframework.test.web.reactive.server.EntityExchangeResult<byte[]> result =
            client.get().uri("/.well-known/encryptor-keys")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().exists("ETag")
                .expectBody(byte[].class).returnResult();
        return new EtagProbe(
            result.getResponseHeaders().getFirst("ETag"),
            new String(result.getResponseBody(), StandardCharsets.UTF_8));
    }

    private record EtagProbe(String etag, String body) {
    }

    @Test
    void query载体经真实Netty往返解回下游明文() {
        ActiveKey k = key();
        Sealed sealed = Boot3ClientSupport.seal("name=7", "/test/hello", "GET", k);
        client.get().uri("/test/hello?name=7&jwe=" + encodePathValue(sealed.compact))
            .exchange()
            .expectStatus().isOk()
            .expectBody(String.class).value(payload -> {
                // 风险点 1 正向 gate：响应经过 EncryptorResponseFilter 装饰并以 dir 回封；
                // 与 NettyWriteResponseFilter 的相对次序在 SCG 2025.0 下成立
                String compact = Boot3ClientSupport.jweCompact(payload);
                byte[] plain = Boot3ClientSupport.decryptResponse("{\"jwe\":\"" + compact + "\"}", sealed.cek);
                assertThat(new String(plain, StandardCharsets.UTF_8)).isEqualTo("Hello, 7");
            });
    }

    @Test
    void json载体往返且明文进下游() {
        ActiveKey k = key();
        Sealed sealed = Boot3ClientSupport.seal("{\"name\":\"j3\"}", "/test/hello", "POST", k);
        client.post().uri("/test/hello")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{\"jwe\":\"" + sealed.compact + "\"}")
            .exchange()
            .expectStatus().isOk()
            .expectBody(String.class).value(payload -> {
                byte[] plain = Boot3ClientSupport.decryptResponse(payload, sealed.cek);
                assertThat(new String(plain, StandardCharsets.UTF_8)).contains("name");
            });
    }

    @Test
    void form载体往返且表单被解析() {
        ActiveKey k = key();
        Sealed sealed = Boot3ClientSupport.seal("name=9", "/test/hello", "POST", k);
        client.post().uri("/test/hello")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .bodyValue(Boot3ClientSupport.formBody(sealed))
            .exchange()
            .expectStatus().isOk()
            .expectBody(String.class).value(payload -> {
                byte[] plain = Boot3ClientSupport.decryptResponse(payload, sealed.cek);
                assertThat(new String(plain, StandardCharsets.UTF_8)).contains("name=[9]");
            });
    }

    @Test
    void 大响应在超限内完整往返() {
        ActiveKey k = key();
        Sealed sealed = Boot3ClientSupport.seal("n=big", "/api/big", "GET", k);
        client.get().uri("/api/big?jwe=" + encodePathValue(sealed.compact))
            .exchange()
            .expectStatus().isOk()
            .expectBody(String.class).value(payload -> {
                byte[] plain = Boot3ClientSupport.decryptResponse(payload, sealed.cek);
                assertThat(new String(plain, StandardCharsets.UTF_8)).isEqualTo(DownstreamEchoServer.BIG_PAYLOAD);
            });
    }

    @Test
    void 篡改报文必须被拒且不进下游() {
        ActiveKey k = key();
        Sealed sealed = Boot3ClientSupport.seal("{\"name\":\"t\"}", "/api/tamper", "POST", k);
        long before = DownstreamEchoServer.hits("/api/tamper");
        String tampered = Boot3ClientSupport.tamper(sealed.compact);
        client.post().uri("/api/tamper")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{\"jwe\":\"" + tampered + "\"}")
            .exchange()
            .expectStatus().isEqualTo(status())
            .expectHeader().exists("X-Encryptor-Trace");
        assertThat(DownstreamEchoServer.hits("/api/tamper")).isEqualTo(before);
    }

    @Test
    void 重放同报文必须被拒() {
        ActiveKey k = key();
        Sealed sealed = Boot3ClientSupport.seal("{\"n\":\"once\"}", "/api/replay", "POST", k);
        // 第一次：合法，进下游，响应回封
        client.post().uri("/api/replay")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{\"jwe\":\"" + sealed.compact + "\"}")
            .exchange().expectStatus().isOk();
        // 第二次：同 compact（同 nonce）必须被防重放拒绝
        client.post().uri("/api/replay")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{\"jwe\":\"" + sealed.compact + "\"}")
            .exchange()
            .expectStatus().isEqualTo(status());
    }

    @Test
    void 未知kid必须被拒() {
        ActiveKey unknownKid = rekey("not-a-kid");
        Sealed sealed = Boot3ClientSupport.seal("{\"n\":\"x\"}", "/api/unknown", "POST", unknownKid);
        client.post().uri("/api/unknown")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{\"jwe\":\"" + sealed.compact + "\"}")
            .exchange()
            .expectStatus().isEqualTo(status());
    }

    @Test
    void 装配面冒烟与micrometer计数递增() {
        // 共享 reactive 装配 + 复制线 gateway 过滤器 + 共享 micrometer 监听器全部在场
        assertThat(context.getBean(EncryptorRuntime.class)).isNotNull();
        assertThat(context.getBean("encryptorGatewayFilter")).isNotNull();
        assertThat(context.getBean("encryptorResponseFilter")).isNotNull();
        assertThat(context.getBean("gatewayJwksEndpointFilter")).isNotNull();
        assertThat(context.getBean(MicrometerEncryptorListener.class)).isNotNull();
        // 路由 locator 非空（动态下游 base-uri）
        assertThat(Flux.from(routeLocator.getRoutes()).collectList().block(Duration.ofSeconds(5))).isNotEmpty();
        // 真实协议调用驱动 micrometer 计数递增（共享 micrometer 线的正向证据）
        ActiveKey k = key();
        Sealed sealed = Boot3ClientSupport.seal("{\"m\":1}", "/api/meter", "POST", k);
        double before = count("encryptor.decrypt", "result", "success");
        client.post().uri("/api/meter")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{\"jwe\":\"" + sealed.compact + "\"}")
            .exchange().expectStatus().isOk();
        assertThat(count("encryptor.decrypt", "result", "success")).isGreaterThan(before);
    }

    private int status() {
        return context.getBean(EncryptorConfig.class).getFailureStatus();
    }

    private double count(String name, String tagKey, String tagValue) {
        io.micrometer.core.instrument.Counter counter = meterRegistry.find(name).tag(tagKey, tagValue).counter();
        return counter == null ? 0 : counter.count();
    }

    /** compact 是 b64url（含 '.'），query 值安全起见整段 URL 编码。 */
    private static String encodePathValue(String compact) {
        try {
            return java.net.URLEncoder.encode(compact, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
