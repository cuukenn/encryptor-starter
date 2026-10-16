package io.github.cuukenn.encryptor.reactive.gateway.filter.rewrite;

import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.facade.IEncryptorFacadeFactory;
import io.github.cuukenn.encryptor.reactive.config.CryptoConfig;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.filter.EncryptorSkipFilter;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 验证 uri 级 crypto-config 取的是"命中的正则 key"对应的配置，而不是用原始 uri 取值
 *
 * @author changgg
 */
public class EncryptorGatewayFilterTest {
    @Test
    public void test_crypto_config_used_by_matched_regex_key() {
        CryptoConfig expected = new CryptoConfig();
        Map<String, CryptoConfig> cryptoConfig = new LinkedHashMap<>();
        cryptoConfig.put("^/test/hello.*", expected);

        GatewayEncryptorConfig config = new GatewayEncryptorConfig();
        config.setCryptoConfig(cryptoConfig);

        final CryptoConfig[] captured = new CryptoConfig[1];
        IEncryptorFacadeFactory<CryptoConfig> facadeFactory = cryptoConf -> {
            captured[0] = cryptoConf;
            // 本用例只关心"传进工厂的是哪份配置"，facade 不会被调用；
            // 但必须返回非 null —— 网关用 exchange 的 ConcurrentHashMap 存 facade，put(key, null) 会抛 NPE
            return new EncryptorFacade(null, null, null, null);
        };

        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test/hello").build());
        EncryptorGatewayFilter filter = new EncryptorGatewayFilter(config, facadeFactory, -13);
        filter.filter(exchange, ex -> Mono.empty()).block();

        Assertions.assertSame(expected, captured[0]);
    }

    /**
     * black-req-content-type 命中的请求不能进入请求解密分支（否则这些请求会被当 JSON 解而 500）
     */
    @Test
    public void test_black_req_content_type_disables_request_decrypt() {
        GatewayEncryptorConfig config = new GatewayEncryptorConfig();
        config.setBlackReqContentType(Collections.singletonList("multipart/form-data"));

        EncryptorGatewayFilter filter = new EncryptorGatewayFilter(config, cryptoConf -> new EncryptorFacade(null, null, null, null), -13);
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/test/hello").contentType(MediaType.MULTIPART_FORM_DATA).build());
        filter.filter(exchange, ex -> Mono.empty()).block();

        Assertions.assertFalse(GatewayKit.isReqEncryptorEnable(exchange));
        // 只影响请求方向，响应方向不受黑名单影响
        Assertions.assertTrue(GatewayKit.isResEncryptorEnable(exchange));
    }

    /**
     * x-skip-encryptor 必须把请求与响应两个方向都关掉
     */
    @Test
    public void test_skip_header_disables_both_directions() {
        GatewayEncryptorConfig config = new GatewayEncryptorConfig();
        EncryptorGatewayFilter gatewayFilter = new EncryptorGatewayFilter(config, cryptoConf -> new EncryptorFacade(null, null, null, null), -13);
        EncryptorSkipFilter skipFilter = new EncryptorSkipFilter(-12);

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/test/hello").header("x-skip-encryptor", "true").build());
        gatewayFilter.filter(exchange, ex -> Mono.empty()).block();
        skipFilter.filter(exchange, ex -> Mono.empty()).block();

        Assertions.assertFalse(GatewayKit.isReqEncryptorEnable(exchange));
        Assertions.assertFalse(GatewayKit.isResEncryptorEnable(exchange));
    }

    /**
     * 过滤器按"命中的配置 key"缓存 facade：同一 key 只构建一次（facadeFactory.apply 内部含 RSA 解析，是这条链路里最贵的部分）。
     */
    @Test
    public void test_facade_cached_by_matched_config_key() {
        CryptoConfig uriConfig = new CryptoConfig();
        Map<String, CryptoConfig> cryptoConfig = new LinkedHashMap<>();
        cryptoConfig.put("^/test/hello.*", uriConfig);

        GatewayEncryptorConfig config = new GatewayEncryptorConfig();
        config.setCryptoConfig(cryptoConfig);

        CountingFacadeFactory factory = new CountingFacadeFactory();
        EncryptorGatewayFilter filter = new EncryptorGatewayFilter(config, factory, -13);

        // 同一 uri 连发两次：第二次必须命中缓存，工厂只被调用一次
        EncryptorFacade first = runAndCapture(filter, "/test/hello");
        EncryptorFacade second = runAndCapture(filter, "/test/hello");
        Assertions.assertEquals(1, factory.count(), "same uri must reuse the cached facade");
        Assertions.assertSame(first, second, "the same facade instance must be reused");

        // 未命中 uri 级正则的请求走默认（null）配置，是另一条缓存，互不串用
        EncryptorFacade defaultFirst = runAndCapture(filter, "/no/match");
        Assertions.assertEquals(2, factory.count(), "default config must get its own cache entry");
        Assertions.assertNotSame(first, defaultFirst, "uri-level and default config must not share a facade");
        Assertions.assertNull(factory.configs.get(1), "default branch must pass null config to the factory");

        runAndCapture(filter, "/no/match");
        Assertions.assertEquals(2, factory.count(), "default facade must also be cached");
    }

    private static EncryptorFacade runAndCapture(EncryptorGatewayFilter filter, String path) {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get(path).build());
        filter.filter(exchange, ex -> Mono.empty()).block();
        return GatewayKit.getEncryptorFacade(exchange);
    }

    /**
     * 记录 apply 调用次数与传入配置的计数工厂
     */
    private static class CountingFacadeFactory implements IEncryptorFacadeFactory<CryptoConfig> {
        private final AtomicInteger applyCount = new AtomicInteger();
        private final List<CryptoConfig> configs = new ArrayList<>();

        @Override
        public EncryptorFacade apply(CryptoConfig config) {
            applyCount.incrementAndGet();
            configs.add(config);
            // 网关用 exchange 的 ConcurrentHashMap 存 facade，put(key, null) 会抛 NPE，必须返回非 null
            return new EncryptorFacade(null, null, null, null);
        }

        int count() {
            return applyCount.get();
        }
    }
}
