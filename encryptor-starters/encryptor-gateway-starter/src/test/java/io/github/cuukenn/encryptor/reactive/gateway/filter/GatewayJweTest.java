package io.github.cuukenn.encryptor.reactive.gateway.filter;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.Direction;
import io.github.cuukenn.encryptor.jose.KeyType;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.reactive.gateway.SmGatewayTestSupport;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayContext;
import io.github.cuukenn.encryptor.reactive.gateway.runtime.CryptoExecutor;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 网关 v2 链路行为测试（gateway.filter 顺序手工串链：gateway(外) → response(内) → 业务）。
 *
 * @author changgg
 */
class GatewayJweTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final String KID = "k1";

    private PublicKey publicKey;
    private DefaultProtocol protocol;
    private GatewayEncryptorConfig gatewayConfig;
    private EncryptorConfig reactiveConfig;

    /** 测试共用一个有界执行器（生产由 GatewayEncryptorConfiguration 提供同一实例）。 */
    private static final CryptoExecutor CRYPTO = CryptoExecutor.create();

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        publicKey = pair.getPublic();
        protocol = DefaultProtocol.builder()
            .key(new DefaultProtocol.KeyMaterial(KID, KeyType.RSA,
                Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())))
            .build();
        gatewayConfig = new GatewayEncryptorConfig();
        reactiveConfig = new EncryptorConfig();
    }

    private String seal(String plaintext, String uri, String method) {
        long ts = System.currentTimeMillis();
        String nonce = UUID.randomUUID().toString();
        Map<String, Object> claims = ContextAad.claims(uri, method, Direction.REQUEST, ts, nonce);
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
            .keyID(KID).customParams(claims).build();
        JWEObject jwe = new JWEObject(header, new Payload(plaintext));
        try {
            jwe.encrypt(new RSAEncrypter((RSAPublicKey) publicKey));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return jwe.serialize();
    }

    private static String tamper(String compact) {
        String[] parts = compact.split("\\.");
        parts[2] = (parts[2].charAt(0) == 'A' ? 'B' : 'A') + parts[2].substring(1);
        return String.join(".", parts);
    }

    /** 客户端视角解开响应 JWE（alg=dir，AAD = protected header ASCII 字节）。 */
    private static byte[] decryptResponse(String responsePayload, byte[] cek) {
        try {
            String compact = JSONUtil.parseObj(responsePayload).getStr("jwe");
            String[] parts = compact.split("\\.");
            byte[] iv = Base64.getUrlDecoder().decode(parts[2]);
            byte[] ciphertext = Base64.getUrlDecoder().decode(parts[3]);
            byte[] tag = Base64.getUrlDecoder().decode(parts[4]);
            byte[] ctAndTag = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, ctAndTag, 0, ciphertext.length);
            System.arraycopy(tag, 0, ctAndTag, ciphertext.length, tag.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            cipher.updateAAD(parts[0].getBytes(StandardCharsets.US_ASCII));
            return cipher.doFinal(ctAndTag);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String responseHeaderJson(String responsePayload) {
        String compact = JSONUtil.parseObj(responsePayload).getStr("jwe");
        return new String(Base64.getUrlDecoder().decode(compact.split("\\.")[0]), StandardCharsets.US_ASCII);
    }

    private EncryptorGatewayFilter gateway() {
        return new EncryptorGatewayFilter(gatewayConfig, reactiveConfig, protocol, CRYPTO);
    }

    private EncryptorResponseFilter response() {
        return new EncryptorResponseFilter(gatewayConfig, reactiveConfig, protocol, CRYPTO);
    }

    @Test
    void query载体解密并改写query参数() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/a").queryParam("jwe", seal("a=1&b=2", "/api/a", "GET")));
        AtomicReference<MultiValueMap<String, String>> seen = new AtomicReference<>();
        gateway().filter(exchange, e -> {
            seen.set(e.getRequest().getQueryParams());
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(seen.get().getFirst("a")).isEqualTo("1");
        assertThat(seen.get().get("b")).containsExactly("2");
        assertThat(seen.get()).doesNotContainKey(GatewayConstant.JWE_PARAM);
    }

    @Test
    void JSON载体解密并换成明文body() {
        String envelope = "{\"jwe\":\"" + seal("{\"name\":\"x\"}", "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body(envelope));
        AtomicReference<String> body = new AtomicReference<>();
        gateway().filter(exchange, e -> DataBufferUtils.join(e.getRequest().getBody())
            .map(buffer -> {
                byte[] bytes = new byte[buffer.readableByteCount()];
                buffer.read(bytes);
                DataBufferUtils.release(buffer);
                return new String(bytes, StandardCharsets.UTF_8);
            })
            .doOnNext(body::set).then()).block(TIMEOUT);
        assertThat(body.get()).isEqualTo("{\"name\":\"x\"}");
    }

    @Test
    void 缺jwe时400且链不继续() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/a"));
        AtomicBoolean called = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            called.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(called).isFalse();
    }

    @Test
    void ContentLength超限时413() {
        String envelope = "{\"jwe\":\"" + seal("{}", "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.CONTENT_LENGTH, String.valueOf(reactiveConfig.getMaxRequestSize() + 1))
                .body(envelope));
        AtomicBoolean called = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            called.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
        assertThat(called).isFalse();
    }

    @Test
    void 实际body超限时413() {
        reactiveConfig.setMaxRequestSize(64);
        StringBuilder big = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            big.append("0123456789");
        }
        String envelope = "{\"jwe\":\"" + seal(big.toString(), "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body(envelope));
        AtomicBoolean called = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            called.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
        assertThat(called).isFalse();
    }

    @Test
    void 篡改报文时400且链不继续() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/a").queryParam("jwe", tamper(seal("a=1", "/api/a", "GET"))));
        AtomicBoolean called = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            called.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(called).isFalse();
    }

    @Test
    void bypass时明文请求原样透传() {
        protocol.runtime().setBypass(true, false);
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/a"));
        AtomicBoolean called = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            called.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(called).isTrue();
        assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void 命中skipUris时透传() {
        gatewayConfig.getSkipUris().add("/api/open.*");
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/open/health"));
        AtomicBoolean called = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            called.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(called).isTrue();
    }

    @Test
    void 命中reqContentType黑名单时透传() {
        gatewayConfig.getSkipReqContentType().add("application/octet-stream");
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_OCTET_STREAM).body("raw"));
        AtomicBoolean called = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            called.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(called).isTrue();
    }

    @Test
    void uri级kid白名单违规时400() {
        gatewayConfig.getCryptoConfig().put("/api/.*", Collections.singletonList("other-kid"));
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/a").queryParam("jwe", seal("a=1", "/api/a", "GET")));
        AtomicBoolean called = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            called.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(called).isFalse();
    }

    @Test
    void 加密请求的响应被加密且可用请求CEK解开() {
        String envelope = "{\"jwe\":\"" + seal("{\"name\":\"x\"}", "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body(envelope));
        AtomicReference<byte[]> cek = new AtomicReference<>();
        GatewayFilterChain inner = e -> {
            GatewayContext ctx = e.getAttribute(GatewayConstant.GATEWAY_CONTEXT_ATTR);
            cek.set(ctx.getJweContext().cek());
            ServerHttpResponse resp = e.getResponse();
            return resp.writeWith(Mono.just(resp.bufferFactory().wrap("hello-downstream".getBytes(StandardCharsets.UTF_8))));
        };
        gateway().filter(exchange, e -> response().filter(e, inner)).block(TIMEOUT);
        String payload = exchange.getResponse().getBodyAsString().block(TIMEOUT);
        assertThat(new String(decryptResponse(payload, cek.get()), StandardCharsets.UTF_8))
            .isEqualTo("hello-downstream");
        assertThat(responseHeaderJson(payload)).contains("\"res\"");
    }

    @Test
    void 无上下文的响应原样透传() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/a"));
        GatewayFilterChain inner = e -> {
            ServerHttpResponse resp = e.getResponse();
            return resp.writeWith(Mono.just(resp.bufferFactory().wrap("plain".getBytes(StandardCharsets.UTF_8))));
        };
        response().filter(exchange, inner).block(TIMEOUT);
        assertThat(exchange.getResponse().getBodyAsString().block(TIMEOUT)).isEqualTo("plain");
    }

    @Test
    void 命中resContentType黑名单时响应透传() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/a"));
        GatewayContext ctx = new GatewayContext();
        ctx.setEncrypted(true);
        exchange.getAttributes().put(GatewayConstant.GATEWAY_CONTEXT_ATTR, ctx);
        gatewayConfig.getSkipResContentType().add("text/plain");
        GatewayFilterChain inner = e -> {
            ServerHttpResponse resp = e.getResponse();
            resp.getHeaders().setContentType(MediaType.TEXT_PLAIN);
            return resp.writeWith(Mono.just(resp.bufferFactory().wrap("plain-text".getBytes(StandardCharsets.UTF_8))));
        };
        response().filter(exchange, inner).block(TIMEOUT);
        assertThat(exchange.getResponse().getBodyAsString().block(TIMEOUT)).isEqualTo("plain-text");
    }

    /**
     * 国密路径专属回归（评审 C2）：SM4-GCM 的 CEK 是 16 字节，"按 CEK 长度猜 enc" 会封成 A128GCM，
     * RSA 路径下猜与不猜结果相同，只有这条用例能区分。
     */
    @Test
    void 国密请求的响应enc仍是SM4GCM() {
        SmGatewayTestSupport sm = new SmGatewayTestSupport();
        SmGatewayTestSupport.Sealed sealed = sm.seal("{\"name\":\"x\"}", "/api/a", "POST");
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/a")
            .contentType(MediaType.APPLICATION_JSON).body("{\"jwe\":\"" + sealed.compact + "\"}"));
        EncryptorGatewayFilter smGateway = new EncryptorGatewayFilter(gatewayConfig, reactiveConfig, sm.protocol, CRYPTO);
        EncryptorResponseFilter smResponse = new EncryptorResponseFilter(gatewayConfig, reactiveConfig, sm.protocol, CRYPTO);
        GatewayFilterChain inner = e -> {
            ServerHttpResponse resp = e.getResponse();
            return resp.writeWith(Mono.just(resp.bufferFactory().wrap("hello-sm".getBytes(StandardCharsets.UTF_8))));
        };
        smGateway.filter(exchange, e -> smResponse.filter(e, inner)).block(TIMEOUT);

        String payload = exchange.getResponse().getBodyAsString().block(TIMEOUT);
        String headerJson = SmGatewayTestSupport.responseHeaderJson(payload);
        cn.hutool.json.JSONObject header = JSONUtil.parseObj(headerJson);
        assertThat(header.getStr("alg")).isEqualTo("dir");
        assertThat(header.getStr("enc")).isEqualTo("SM4-GCM");
        assertThat(new String(SmGatewayTestSupport.sm4DecryptResponse(payload, sealed.cek), StandardCharsets.UTF_8))
            .isEqualTo("hello-sm");
    }

    /** 非法 JSON 信封必须按 failure-status 收口（评审 I5）：不能让 hutool JSONException 冒泡成 500。 */
    @Test
    void 非法JSON信封回failureStatus而不是500() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/a")
            .contentType(MediaType.APPLICATION_JSON).body("{not-a-json-envelope"));
        AtomicBoolean chained = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            chained.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(chained.get()).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    /** 失败响应带排障 trace 头（评审 I11）。 */
    @Test
    void 失败响应带trace头() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/a")
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"jwe\":\"" + tamper(seal("{\"name\":\"x\"}", "/api/a", "POST")) + "\"}"));
        gateway().filter(exchange, e -> Mono.empty()).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(exchange.getResponse().getHeaders().getFirst(EncryptorConstant.TRACE_HEADER)).isNotBlank();
    }

    /** body 已被换成 JWE JSON：下游声明的 Content-Encoding 必须去掉（评审 I18），否则客户端按 gzip 解出乱码。 */
    @Test
    void 下游声明ContentEncoding时封装后必须去掉() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/a")
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"jwe\":\"" + seal("{\"name\":\"x\"}", "/api/a", "POST") + "\"}"));
        GatewayFilterChain inner = e -> {
            ServerHttpResponse resp = e.getResponse();
            resp.getHeaders().set(HttpHeaders.CONTENT_ENCODING, "gzip");
            return resp.writeWith(Mono.just(resp.bufferFactory().wrap("gz".getBytes(StandardCharsets.UTF_8))));
        };
        gateway().filter(exchange, e -> response().filter(e, inner)).block(TIMEOUT);
        assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.CONTENT_ENCODING)).isNull();
    }
}
