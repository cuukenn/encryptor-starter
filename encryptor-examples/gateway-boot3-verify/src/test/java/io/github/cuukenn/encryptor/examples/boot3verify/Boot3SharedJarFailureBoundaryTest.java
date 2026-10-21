package io.github.cuukenn.encryptor.examples.boot3verify;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.Direction;
import io.github.cuukenn.encryptor.jose.KeyType;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.DiscoveryConfig;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import io.github.cuukenn.encryptor.reactive.gateway.discovery.JwksEndpointFilter;
import io.github.cuukenn.encryptor.reactive.gateway.filter.EncryptorGatewayFilter;
import io.github.cuukenn.encryptor.reactive.gateway.filter.EncryptorResponseFilter;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayContext;
import io.github.cuukenn.encryptor.reactive.gateway.runtime.CryptoExecutor;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 共享 gateway jar 在 Boot 3.5 的失败边界（固定证据，非倡议）。
 *
 * <p>Spring 6.x 相比 Spring 5.3（javax 线的编译目标）删改了两个 reactive API：</p>
 * <ol>
 *   <li>{@code ServerHttpRequest#getMethodValue()} —— 方法被移除（NoSuchMethodError）；
 *       命中点：{@code JwksEndpointFilter.java:56}、{@code EncryptorGatewayFilter.java:77}、
 *       {@code EncryptorResponseFilter.java:104/153}；</li>
 *   <li>{@code ServerHttpResponse#getStatusCode()} —— 返回类型从 {@code HttpStatus} 改为
 *       {@code HttpStatusCode}，字节码描述符变化（同样 NoSuchMethodError）；
 *       命中点：{@code EncryptorResponseFilter.java:151/159/167}。</li>
 * </ol>
 *
 * <p>JWKS 过滤器是 order -14 的 WebFilter——任何请求最先经过，端到端链路无法启动；
 * 这就是真实 HTTP 用例只能看到 "Connection prematurely closed" 的原因（服务器端打
 * NoSuchMethodError 后直接断连）。机械包名替换（javax→jakarta）修不了这两类 API 差异。</p>
 *
 * @author changgg
 */
class Boot3SharedJarFailureBoundaryTest {
    private static final String KID = "k1";

    private static KeyPair pair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 与 javax 线 GatewayJweTest 同口径的协议栈（只用于构造过滤器实例）。 */
    private static DefaultProtocol protocol() {
        try {
            KeyPair pair = pair();
            return DefaultProtocol.builder()
                .key(new DefaultProtocol.KeyMaterial(KID, KeyType.RSA,
                    Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                    Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())))
                .build();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String seal(String plaintext, String uri, String method) {
        try {
            long ts = System.currentTimeMillis();
            String nonce = UUID.randomUUID().toString();
            Map<String, Object> claims = ContextAad.claims(uri, method, Direction.REQUEST, ts, nonce);
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID(KID).customParams(claims).build();
            JWEObject jwe = new JWEObject(header, new Payload(plaintext));
            jwe.encrypt(new RSAEncrypter((RSAPublicKey) pair().getPublic()));
            return jwe.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 风险点 2 前置：请求过滤器在 getMethodValue（method 上下文绑定）处必然中断（500 覆盖不到）。 */
    @Test
    void 请求过滤器在getMethodValue处NoSuchMethodError() {
        String envelope = "{\"jwe\":\"" + seal("{}", "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body(envelope));
        EncryptorGatewayFilter filter = new EncryptorGatewayFilter(new GatewayEncryptorConfig(),
            new EncryptorConfig(), protocol(), CryptoExecutor.create());
        assertThatThrownBy(() -> filter.filter(exchange, e -> Mono.empty()).block())
            .isInstanceOf(NoSuchMethodError.class)
            .hasMessageContaining("getMethodValue");
    }

    /** 同口径再证 JWKS 发现过滤器（order -14 的 WebFilter：任何请求最先触发，端到端必死）。 */
    @Test
    void jwks发现过滤器同样在getMethodValue处中断() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/anything").build());
        JwksEndpointFilter filter = new JwksEndpointFilter(protocol().keys(),
            new DiscoveryConfig(), -14);
        assertThatThrownBy(() -> filter.filter(exchange, chain -> Mono.empty()).block())
            .isInstanceOf(NoSuchMethodError.class)
            .hasMessageContaining("getMethodValue");
    }

    /** 风险点 1 前置：响应过滤器在带加密上下文的写出路径在 getStatusCode 处必然中断。 */
    @Test
    void 响应过滤器在getStatusCode处NoSuchMethodError() {
        GatewayContext ctx = new GatewayContext();
        ctx.setEncrypted(true);
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body("{}"));
        exchange.getAttributes().put(GatewayConstant.GATEWAY_CONTEXT_ATTR, ctx);
        EncryptorResponseFilter filter = new EncryptorResponseFilter(new GatewayEncryptorConfig(),
            new EncryptorConfig(), protocol(), CryptoExecutor.create());
        try {
            assertThatThrownBy(() -> filter.filter(exchange, e -> e.getResponse().writeWith(
                    Mono.just(e.getResponse().bufferFactory().wrap("hello".getBytes(StandardCharsets.UTF_8)))))
                .block())
                .isInstanceOf(NoSuchMethodError.class)
                .hasMessageContaining("getStatusCode");
        } finally {
            exchange.getAttributes().remove(GatewayConstant.GATEWAY_CONTEXT_ATTR);
            ctx.destroy();
        }
    }
}
