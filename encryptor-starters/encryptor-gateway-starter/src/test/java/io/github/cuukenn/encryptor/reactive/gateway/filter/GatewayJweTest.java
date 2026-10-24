package io.github.cuukenn.encryptor.reactive.gateway.filter;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.Direction;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.jose.KeyType;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.reactive.gateway.SmGatewayTestSupport;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayContext;
import io.github.cuukenn.encryptor.reactive.gateway.runtime.CryptoExecutor;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.NettyWriteResponseFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.slf4j.LoggerFactory.getLogger;

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

    @Test
    void codec之外的失败分支也触发审计回调() throws Exception {
        // 缺载体 / kid 白名单 / 执行器拒绝等失败不经过 codec，此前审计对它们全盲；
        // codec 路径的失败由 JweCodec 审计，这里不会重复出现
        java.util.List<EncryptorFailure> failures = new java.util.ArrayList<>();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        DefaultProtocol audited = DefaultProtocol.builder()
            .key(new DefaultProtocol.KeyMaterial(KID, KeyType.RSA,
                Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())))
            .listener(new EncryptorListener() {
                @Override
                public void onDecryptFailure(EncryptorFailure failure, Throwable cause) {
                    failures.add(failure);
                }
            }).build();
        EncryptorGatewayFilter filter = new EncryptorGatewayFilter(gatewayConfig, reactiveConfig, audited, CRYPTO);
        try {
            // 1) 缺载体 + require-encrypted
            reactiveConfig.setRequireEncrypted(true);
            MockServerWebExchange missing = MockServerWebExchange.from(MockServerHttpRequest.get("/api/a"));
            filter.filter(missing, e -> Mono.empty()).block(TIMEOUT);

            // 2) kid 白名单拒绝（seal 用同一密钥对，保证解密先成功、失败只来自白名单）
            // 直接 put 时不需要 yml 的括号写法：括号会被当正则字符类
            gatewayConfig.getCryptoConfig().put("/api/.*", java.util.Collections.singletonList("other-kid"));
            MockServerWebExchange kidDenied = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/a").queryParam("jwe",
                    sealWith("x", "/api/a", "GET", pair.getPublic())));
            filter.filter(kidDenied, e -> Mono.empty()).block(TIMEOUT);

            assertThat(failures).containsExactly(EncryptorFailure.MISSING, EncryptorFailure.ALG_NOT_ALLOWED);
        } finally {
            reactiveConfig.setRequireEncrypted(false);
            gatewayConfig.getCryptoConfig().clear();
        }
    }

    @Test
    void 过滤器顺序门面在外响应在内() {
        EncryptorResponseFilter responseFilter =
            new EncryptorResponseFilter(gatewayConfig, reactiveConfig, protocol, CRYPTO);
        assertThat(gateway().getOrder()).isLessThan(responseFilter.getOrder());
        assertThat(responseFilter.getOrder()).isEqualTo(NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1);
    }

    @Test
    void skip名单含eventStream时启动告警() {
        gatewayConfig.getSkipResContentType().add("text/event-stream");
        Logger logger = (Logger) getLogger(EncryptorGatewayFilter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            new EncryptorGatewayFilter(gatewayConfig, reactiveConfig, protocol, CRYPTO);
        } finally {
            logger.detachAppender(appender);
        }
        assertThat(appender.list).anyMatch(e -> e.getLevel() == Level.WARN
            && e.getFormattedMessage().contains("不加密"));
    }

    private String seal(String plaintext, String uri, String method) {
        return sealWith(plaintext, uri, method, publicKey);
    }

    private String sealWith(String plaintext, String uri, String method, java.security.PublicKey key) {
        long ts = System.currentTimeMillis();
        String nonce = UUID.randomUUID().toString();
        Map<String, Object> claims = ContextAad.claims(uri, method, Direction.REQUEST, ts, nonce);
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
            .keyID(KID).customParams(claims).build();
        JWEObject jwe = new JWEObject(header, new Payload(plaintext));
        try {
            jwe.encrypt(new RSAEncrypter((RSAPublicKey) key));
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
    void 请求完成后清理上下文并清零敏感数据() {
        String envelope = "{\"jwe\":\"" + seal("{\"name\":\"x\"}", "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body(envelope));
        AtomicReference<byte[]> sensitivePlaintext = new AtomicReference<>();
        AtomicReference<byte[]> sensitiveCek = new AtomicReference<>();
        gateway().filter(exchange, e -> {
            GatewayContext context = e.getAttribute(GatewayConstant.GATEWAY_CONTEXT_ATTR);
            sensitivePlaintext.set(context.getJweContext().plaintext());
            sensitiveCek.set(context.getJweContext().cek());
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat((Object) exchange.getAttribute(GatewayConstant.GATEWAY_CONTEXT_ATTR)).isNull();
        assertThat(sensitivePlaintext.get()).containsOnly((byte) 0);
        assertThat(sensitiveCek.get()).containsOnly((byte) 0);
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
    void vndApiJson载体按JSON解析() {
        String envelope = "{\"jwe\":\"" + seal("{\"name\":\"x\"}", "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a")
                .contentType(MediaType.parseMediaType("application/vnd.api+json")).body(envelope));
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
    void query载体明文按form语义解码且uri保持已编码形态() {
        // 客户端契约：query 明文是 form 语义的 urlencoded（与 servlet parseQuery 的 URLDecoder 同口径，
        // 空格编码为 +）；下游参数视图拿到的是【解码值】（与 servlet 侧一致），URI 重建保持已编码形态
        String encoded = "q=%E5%BC%A0%E4%B8%89&x=a%20b&plus=a+b";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/a").queryParam("jwe", seal(encoded, "/api/a", "GET")));
        AtomicReference<URI> uri = new AtomicReference<>();
        AtomicReference<MultiValueMap<String, String>> params = new AtomicReference<>();
        gateway().filter(exchange, e -> {
            uri.set(e.getRequest().getURI());
            params.set(e.getRequest().getQueryParams());
            return Mono.empty();
        }).block(TIMEOUT);
        // '+' 按语义解码后重建为等价的 %20（form 语义下两者都解码为空格）
        assertThat(uri.get().getRawQuery()).isEqualTo("q=%E5%BC%A0%E4%B8%89&x=a%20b&plus=a%20b");
        assertThat(uri.get().toString()).doesNotContain("%25");
        assertThat(params.get().getFirst("q")).isEqualTo("张三");
        assertThat(params.get().getFirst("x")).isEqualTo("a b");
        // form 语义：+ 解码为空格（此前网关侧按 URI 语义保留 +，与 servlet 分叉）
        assertThat(params.get().getFirst("plus")).isEqualTo("a b");
    }

    @Test
    void query载体明文非法编码时回failureStatus而不500() {
        // 尾部残缺的 % 转义（"100%"）在 form 语义解码时就非法：必须在过滤器内变成 failure-status，而不是 500
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/a").queryParam("jwe", seal("q=100%", "/api/a", "GET")));
        AtomicBoolean called = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            // 路由阶段会读取 getURI()：非法编码必须在过滤器内变成 failure-status，而不是在这里炸出 500
            e.getRequest().getURI();
            called.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(called).isFalse();
    }

    @Test
    void JSON明文body可被二次订阅() {
        String envelope = "{\"jwe\":\"" + seal("{\"name\":\"x\"}", "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body(envelope));
        AtomicReference<String> first = new AtomicReference<>();
        AtomicReference<String> second = new AtomicReference<>();
        gateway().filter(exchange, e -> {
            Flux<DataBuffer> body = e.getRequest().getBody();
            return bodyAsString(body).doOnNext(first::set)
                .then(bodyAsString(body)).doOnNext(second::set)
                .then();
        }).block(TIMEOUT);
        assertThat(first.get()).isEqualTo("{\"name\":\"x\"}");
        assertThat(second.get()).isEqualTo("{\"name\":\"x\"}");
    }

    /** 直接消费首个 DataBuffer，模拟 Retry 类过滤器对同一 body Flux 的二次订阅。 */
    private static Mono<String> bodyAsString(Flux<DataBuffer> body) {
        return body.next()
            .map(buffer -> {
                byte[] bytes = new byte[buffer.readableByteCount()];
                buffer.read(bytes);
                DataBufferUtils.release(buffer);
                return new String(bytes, StandardCharsets.UTF_8);
            })
            .defaultIfEmpty("");
    }

    @Test
    void 缺jwe时400且链不继续() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/a"));
        AtomicBoolean called = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            // 路由阶段会读取 getURI()：非法编码必须在过滤器内变成 failure-status，而不是在这里炸出 500
            e.getRequest().getURI();
            called.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(called).isFalse();
    }

    @Test
    void 失败日志包含trace与请求路径() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/missing"));
        Logger logger = (Logger) getLogger(EncryptorGatewayFilter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            gateway().filter(exchange, e -> Mono.empty()).block(TIMEOUT);
        } finally {
            logger.detachAppender(appender);
        }
        assertThat(appender.list).anyMatch(e -> e.getLevel() == Level.WARN
            && e.getFormattedMessage().contains("/api/missing")
            && e.getFormattedMessage().contains("trace:"));
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

    /**
     * chunked 请求没有 Content-Length：必须在读取过程中就按 max-request-size 截断，
     * 不能先把整个 body 拼进堆、再按实际长度拒绝。
     */
    @Test
    void chunkedBody超限时不得读完整个流() {
        reactiveConfig.setMaxRequestSize(64);
        DefaultDataBufferFactory bufferFactory = new DefaultDataBufferFactory();
        AtomicInteger emitted = new AtomicInteger();
        Flux<DataBuffer> body = Flux.range(0, 100)
            .map(i -> (DataBuffer) bufferFactory.wrap(new byte[10]))
            .doOnNext(buffer -> emitted.incrementAndGet());
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body(body));
        AtomicBoolean called = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            called.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
        assertThat(called).isFalse();
        assertThat(emitted.get()).isLessThan(100);
    }

    @Test
    void 篡改报文时400且链不继续() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/a").queryParam("jwe", tamper(seal("a=1", "/api/a", "GET"))));
        AtomicBoolean called = new AtomicBoolean();
        gateway().filter(exchange, e -> {
            // 路由阶段会读取 getURI()：非法编码必须在过滤器内变成 failure-status，而不是在这里炸出 500
            e.getRequest().getURI();
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
    void 非空JSON明文透传时下游仍能读到原始body() {
        reactiveConfig.setRequireEncrypted(false);
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body("{\"foo\":1}"));
        AtomicReference<String> body = new AtomicReference<>();
        gateway().filter(exchange, e -> DataBufferUtils.join(e.getRequest().getBody())
            .map(buffer -> {
                byte[] bytes = new byte[buffer.readableByteCount()];
                buffer.read(bytes);
                DataBufferUtils.release(buffer);
                return new String(bytes, StandardCharsets.UTF_8);
            })
            .doOnNext(body::set).then()).block(TIMEOUT);
        assertThat(body.get()).isEqualTo("{\"foo\":1}");
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
            // 路由阶段会读取 getURI()：非法编码必须在过滤器内变成 failure-status，而不是在这里炸出 500
            e.getRequest().getURI();
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
            cek.set(Arrays.copyOf(ctx.getJweContext().cek(), ctx.getJweContext().cek().length));
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
    void 流式writeAndFlushWith响应也被加密() {
        String envelope = "{\"jwe\":\"" + seal("{\"name\":\"x\"}", "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body(envelope));
        AtomicReference<byte[]> cek = new AtomicReference<>();
        GatewayFilterChain inner = e -> {
            GatewayContext ctx = e.getAttribute(GatewayConstant.GATEWAY_CONTEXT_ATTR);
            cek.set(Arrays.copyOf(ctx.getJweContext().cek(), ctx.getJweContext().cek().length));
            ServerHttpResponse resp = e.getResponse();
            return resp.writeAndFlushWith(Flux.just(
                Mono.just(resp.bufferFactory().wrap("hello-".getBytes(StandardCharsets.UTF_8))),
                Mono.just(resp.bufferFactory().wrap("stream".getBytes(StandardCharsets.UTF_8)))));
        };
        gateway().filter(exchange, e -> response().filter(e, inner)).block(TIMEOUT);
        String payload = exchange.getResponse().getBodyAsString().block(TIMEOUT);
        assertThat(payload).contains("\"jwe\"");
        assertThat(new String(decryptResponse(payload, cek.get()), StandardCharsets.UTF_8))
            .isEqualTo("hello-stream");
        assertThat(responseHeaderJson(payload)).contains("\"res\"");
    }

    @Test
    void 流式响应命中contentType黑名单时仍透传() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/a"));
        GatewayContext ctx = new GatewayContext();
        ctx.setEncrypted(true);
        exchange.getAttributes().put(GatewayConstant.GATEWAY_CONTEXT_ATTR, ctx);
        gatewayConfig.getSkipResContentType().add("text/plain");
        GatewayFilterChain inner = e -> {
            ServerHttpResponse resp = e.getResponse();
            resp.getHeaders().setContentType(MediaType.TEXT_PLAIN);
            return resp.writeAndFlushWith(Flux.just(
                Mono.just(resp.bufferFactory().wrap("hello-".getBytes(StandardCharsets.UTF_8))),
                Mono.just(resp.bufferFactory().wrap("stream".getBytes(StandardCharsets.UTF_8)))));
        };
        response().filter(exchange, inner).block(TIMEOUT);
        assertThat(exchange.getResponse().getBodyAsString().block(TIMEOUT)).isEqualTo("hello-stream");
    }

    @Test
    void 网关200空body也封装为空明文JWE() {
        String envelope = "{\"jwe\":\"" + seal("{}", "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body(envelope));
        AtomicReference<byte[]> cek = new AtomicReference<>();
        GatewayFilterChain inner = e -> {
            GatewayContext ctx = e.getAttribute(GatewayConstant.GATEWAY_CONTEXT_ATTR);
            cek.set(Arrays.copyOf(ctx.getJweContext().cek(), ctx.getJweContext().cek().length));
            return e.getResponse().writeWith(Flux.empty());
        };
        gateway().filter(exchange, e -> response().filter(e, inner)).block(TIMEOUT);
        String payload = exchange.getResponse().getBodyAsString().block(TIMEOUT);
        assertThat(payload).contains("\"jwe\"");
        assertThat(decryptResponse(payload, cek.get())).isEmpty();
        assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
    }

    @Test
    void 网关204响应不加密也不带body() {
        String envelope = "{\"jwe\":\"" + seal("{}", "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body(envelope));
        GatewayFilterChain inner = e -> {
            ServerHttpResponse resp = e.getResponse();
            resp.setStatusCode(HttpStatus.NO_CONTENT);
            resp.getHeaders().setContentType(MediaType.TEXT_PLAIN);
            return resp.writeWith(Mono.just(resp.bufferFactory().wrap("secret".getBytes(StandardCharsets.UTF_8))));
        };
        gateway().filter(exchange, e -> response().filter(e, inner)).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(exchange.getResponse().getBodyAsString().block(TIMEOUT)).isEmpty();
        assertThat(exchange.getResponse().getHeaders().getContentType()).isNotEqualTo(MediaType.APPLICATION_JSON);
    }

    @Test
    void 网关HEAD响应不加密也不带body() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.head("/api/a").queryParam("jwe", seal("", "/api/a", "HEAD")));
        GatewayFilterChain inner = e -> {
            ServerHttpResponse resp = e.getResponse();
            return resp.writeWith(Mono.just(resp.bufferFactory().wrap("secret".getBytes(StandardCharsets.UTF_8))));
        };
        gateway().filter(exchange, e -> response().filter(e, inner)).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(exchange.getResponse().getBodyAsString().block(TIMEOUT)).isEmpty();
    }

    @Test
    void 网关302空body直接透传() {
        String envelope = "{\"jwe\":\"" + seal("{}", "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body(envelope));
        GatewayFilterChain inner = e -> {
            ServerHttpResponse resp = e.getResponse();
            resp.setStatusCode(HttpStatus.FOUND);
            resp.getHeaders().setLocation(URI.create("/login"));
            return resp.writeWith(Mono.just(resp.bufferFactory().wrap(new byte[0])));
        };
        gateway().filter(exchange, e -> response().filter(e, inner)).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(exchange.getResponse().getHeaders().getLocation()).isEqualTo(URI.create("/login"));
        assertThat(exchange.getResponse().getBodyAsString().block(TIMEOUT)).isEmpty();
        assertThat(exchange.getResponse().getHeaders().getContentType()).isNotEqualTo(MediaType.APPLICATION_JSON);
    }

    @Test
    void 网关302带body仍加密() {
        String envelope = "{\"jwe\":\"" + seal("{}", "/api/a", "POST") + "\"}";
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON).body(envelope));
        AtomicReference<byte[]> cek = new AtomicReference<>();
        GatewayFilterChain inner = e -> {
            GatewayContext ctx = e.getAttribute(GatewayConstant.GATEWAY_CONTEXT_ATTR);
            cek.set(Arrays.copyOf(ctx.getJweContext().cek(), ctx.getJweContext().cek().length));
            ServerHttpResponse resp = e.getResponse();
            resp.setStatusCode(HttpStatus.FOUND);
            resp.getHeaders().setLocation(URI.create("/login"));
            return resp.writeWith(Mono.just(resp.bufferFactory().wrap("redirect-body".getBytes(StandardCharsets.UTF_8))));
        };
        gateway().filter(exchange, e -> response().filter(e, inner)).block(TIMEOUT);
        String payload = exchange.getResponse().getBodyAsString().block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(exchange.getResponse().getHeaders().getLocation()).isEqualTo(URI.create("/login"));
        assertThat(payload).contains("\"jwe\"");
        assertThat(new String(decryptResponse(payload, cek.get()), StandardCharsets.UTF_8))
            .isEqualTo("redirect-body");
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

    /** 响应方向同理：流式/chunked 响应必须在读取过程中按 max-response-size 截断。 */
    @Test
    void 请求侧执行器拒绝时回503且补审计回调() throws Exception {
        // 请求解密走 crypto scheduler：队列满/disposed 时必须 503（不能伪装成客户端 4xx）；
        // 失败分支的 onDecryptFailure 审计必须被补发（用 recording listener 钉住）
        java.util.List<EncryptorFailure> failures = new java.util.ArrayList<>();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        DefaultProtocol audited = DefaultProtocol.builder()
            .key(new DefaultProtocol.KeyMaterial(KID, KeyType.RSA,
                Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())))
            .listener(new EncryptorListener() {
                @Override
                public void onDecryptFailure(EncryptorFailure failure, Throwable cause) {
                    failures.add(failure);
                }
            }).build();
        CryptoExecutor disposed = CryptoExecutor.create();
        disposed.dispose();
        EncryptorGatewayFilter filter = new EncryptorGatewayFilter(gatewayConfig, reactiveConfig, audited, disposed);
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/a").queryParam("jwe",
                sealWith("x=1", "/api/a", "GET", pair.getPublic())));
        AtomicBoolean called = new AtomicBoolean();
        filter.filter(exchange, e -> {
            called.set(true);
            return Mono.empty();
        }).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(called).isFalse();
        assertThat(failures).containsExactly(EncryptorFailure.INTERNAL);
    }

    @Test
    void 订阅取消时清理上下文并清零敏感数据() throws Exception {
        // 下游 Mono.never() + dispose 模拟客户端断连/超时取消：doFinally(CANCEL) 必须移除
        // GatewayContext 并清零 CEK/明文（此前只有正常完成信号被验证过）
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/api/a").contentType(MediaType.APPLICATION_JSON)
                .body("{\"jwe\":\"" + seal("{\"k\":\"v\"}", "/api/a", "POST") + "\"}"));
        AtomicReference<GatewayContext> captured = new AtomicReference<>();
        reactor.core.Disposable disposable = gateway().filter(exchange, e -> {
            captured.set(e.getAttribute(GatewayConstant.GATEWAY_CONTEXT_ATTR));
            return Mono.never();
        }).subscribe();
        // 等解密完成、上下文已登记后再取消
        long deadline = System.currentTimeMillis() + TIMEOUT.toMillis();
        while (captured.get() == null && System.currentTimeMillis() < deadline) {
            Thread.sleep(10);
        }
        assertThat(captured.get()).isNotNull();
        byte[] cek = captured.get().getJweContext().cek();
        disposable.dispose();
        // doFinally 在取消信号上执行清理（异步，稍等）
        deadline = System.currentTimeMillis() + TIMEOUT.toMillis();
        while (exchange.getAttribute(GatewayConstant.GATEWAY_CONTEXT_ATTR) != null
            && System.currentTimeMillis() < deadline) {
            Thread.sleep(10);
        }
        assertThat((Object) exchange.getAttribute(GatewayConstant.GATEWAY_CONTEXT_ATTR)).isNull();
        assertThat(cek).containsOnly((byte) 0);
    }

    @Test
    void 响应加密被拒绝时回503() throws Exception {
        String compact = seal("a=1", "/api/a", "GET");
        JweContext jweContext = protocol.openRequest(compact, "/api/a", "GET");
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/a"));
        GatewayContext ctx = new GatewayContext();
        ctx.setEncrypted(true);
        ctx.setJweContext(jweContext);
        exchange.getAttributes().put(GatewayConstant.GATEWAY_CONTEXT_ATTR, ctx);

        CryptoExecutor disposed = CryptoExecutor.create();
        disposed.dispose();
        EncryptorResponseFilter filter = new EncryptorResponseFilter(gatewayConfig, reactiveConfig, protocol, disposed);
        GatewayFilterChain inner = e -> e.getResponse().writeWith(
            Mono.just(e.getResponse().bufferFactory().wrap("hello".getBytes(StandardCharsets.UTF_8))));

        filter.filter(exchange, inner).block(TIMEOUT);

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void chunkedResponse超限时不得读完整个流() {
        reactiveConfig.setMaxResponseSize(64);
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/a"));
        GatewayContext ctx = new GatewayContext();
        ctx.setEncrypted(true);
        exchange.getAttributes().put(GatewayConstant.GATEWAY_CONTEXT_ATTR, ctx);
        DefaultDataBufferFactory bufferFactory = new DefaultDataBufferFactory();
        AtomicInteger emitted = new AtomicInteger();
        GatewayFilterChain inner = e -> e.getResponse().writeWith(
            Flux.range(0, 100)
                .map(i -> (DataBuffer) bufferFactory.wrap(new byte[10]))
                .doOnNext(buffer -> emitted.incrementAndGet()));
        response().filter(exchange, inner).block(TIMEOUT);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(emitted.get()).isLessThan(100);
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
