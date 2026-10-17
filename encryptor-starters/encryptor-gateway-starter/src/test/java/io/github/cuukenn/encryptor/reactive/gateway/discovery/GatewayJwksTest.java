package io.github.cuukenn.encryptor.reactive.gateway.discovery;

import io.github.cuukenn.encryptor.jose.KeyType;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.DiscoveryConfig;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 网关侧 JWKS 发现端点：网关自己响应，不转发下游；响应体与 servlet 侧同形。
 *
 * @author changgg
 */
class GatewayJwksTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final String DISCOVERY_PATH = "/.well-known/encryptor-keys";

    private DefaultProtocol protocol;
    private EncryptorConfig reactiveConfig;
    private AtomicInteger forwarded;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        protocol = DefaultProtocol.builder()
            .key(new DefaultProtocol.KeyMaterial("k1", KeyType.RSA,
                Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())))
            .build();
        reactiveConfig = new EncryptorConfig();
        forwarded = new AtomicInteger();
    }

    private JwksEndpointFilter newFilter() {
        return new JwksEndpointFilter(protocol.keys(), reactiveConfig.getDiscovery());
    }

    private MockServerWebExchange invoke(JwksEndpointFilter filter, MockServerHttpRequest.BaseBuilder<?> request) {
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        GatewayFilterChain downstream = ex -> {
            forwarded.incrementAndGet();
            ex.getResponse().setStatusCode(HttpStatus.OK);
            return ex.getResponse().setComplete();
        };
        filter.filter(exchange, downstream).block(TIMEOUT);
        return exchange;
    }

    @Test
    void JWKS路径GET返回公钥且不转发下游() {
        MockServerWebExchange exchange = invoke(newFilter(), MockServerHttpRequest.get(DISCOVERY_PATH));
        assertThat(forwarded.get()).isZero();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(exchange.getResponse().getHeaders().getContentType().isCompatibleWith(
            org.springframework.http.MediaType.APPLICATION_JSON)).isTrue();
        String body = exchange.getResponse().getBodyAsString().block(TIMEOUT);
        assertThat(body).contains("k1").contains("kty").contains("RSA");
        assertThat(body).doesNotContain("\"d\"");
        assertThat(exchange.getResponse().getHeaders().getFirst("ETag")).isNotNull();
        assertThat(exchange.getResponse().getHeaders().getFirst("Cache-Control"))
            .isEqualTo("public, max-age=300");
    }

    @Test
    void IfNoneMatch命中返回304且无体() {
        JwksEndpointFilter filter = newFilter();
        MockServerWebExchange first = invoke(filter, MockServerHttpRequest.get(DISCOVERY_PATH));
        String etag = first.getResponse().getHeaders().getFirst("ETag");
        assertThat(etag).isNotNull();

        MockServerWebExchange second = invoke(filter,
            MockServerHttpRequest.get(DISCOVERY_PATH).header("If-None-Match", etag));
        assertThat(forwarded.get()).isZero();
        assertThat(second.getResponse().getStatusCode()).isEqualTo(HttpStatus.NOT_MODIFIED);
        String body = second.getResponse().getBodyAsString().block(TIMEOUT);
        assertThat(body).isEmpty();
    }

    @Test
    void enable为false时原样放行下游() {
        DiscoveryConfig discovery = reactiveConfig.getDiscovery();
        discovery.setEnable(false);
        MockServerWebExchange exchange = invoke(newFilter(), MockServerHttpRequest.get(DISCOVERY_PATH));
        assertThat(forwarded.get()).isEqualTo(1);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void 非GET方法不拦截() {
        invoke(newFilter(), MockServerHttpRequest.post(DISCOVERY_PATH));
        assertThat(forwarded.get()).isEqualTo(1);
    }

    @Test
    void 其他路径不拦截() {
        invoke(newFilter(), MockServerHttpRequest.get("/api/other"));
        assertThat(forwarded.get()).isEqualTo(1);
    }
}
