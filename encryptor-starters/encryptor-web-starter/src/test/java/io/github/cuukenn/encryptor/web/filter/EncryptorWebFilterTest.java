package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.facade.IEncryptorFacadeFactory;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 验证 uri 级 crypto-config 取的是"命中的正则 key"对应的配置，而不是用原始 uri 取值
 *
 * @author changgg
 */
public class EncryptorWebFilterTest {
    @Test
    public void test_crypto_config_used_by_matched_regex_key() throws Exception {
        CryptoConfig expected = new CryptoConfig();
        Map<String, CryptoConfig> cryptoConfig = new LinkedHashMap<>();
        cryptoConfig.put("^/test/hello.*", expected);

        WebEncryptorConfig config = new WebEncryptorConfig();
        config.setCryptoConfig(cryptoConfig);

        final CryptoConfig[] captured = new CryptoConfig[1];
        IEncryptorFacadeFactory<CryptoConfig> facadeFactory = cryptoConf -> {
            captured[0] = cryptoConf;
            return null;
        };

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/test/hello");
        EncryptorWebFilter filter = new EncryptorWebFilter(config, facadeFactory);
        filter.doFilterInternal(request, new MockHttpServletResponse(), new MockFilterChain());

        Assertions.assertSame(expected, captured[0]);
    }

    @Test
    public void test_context_cleared_after_request() throws Exception {
        WebEncryptorConfig config = new WebEncryptorConfig();
        config.setCryptoConfig(new LinkedHashMap<>());

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/test/hello");
        EncryptorWebFilter filter = new EncryptorWebFilter(config, cryptoConf -> null);
        filter.doFilterInternal(request, new MockHttpServletResponse(), new MockFilterChain());

        // 请求结束后上下文必须被清理：Servlet 线程池复用线程时会串号
        Assertions.assertFalse(WebContext.current().isEncryptor());
        Assertions.assertFalse(WebContext.current().isReqEncryptor());
        Assertions.assertNull(WebContext.current().getEncryptorFacade());
        Assertions.assertNull(WebContext.current().getConfig());
    }

    @Test
    public void test_context_cleared_when_chain_throws() throws Exception {
        WebEncryptorConfig config = new WebEncryptorConfig();
        config.setCryptoConfig(new LinkedHashMap<>());

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/test/hello");
        EncryptorWebFilter filter = new EncryptorWebFilter(config, cryptoConf -> null);
        FilterChain failingChain = (req, res) -> {
            throw new ServletException("boom");
        };

        Assertions.assertThrows(ServletException.class,
                () -> filter.doFilterInternal(request, new MockHttpServletResponse(), failingChain));

        // 异常路径同样要清理，否则下一个请求会继承上一个请求的密钥配置
        Assertions.assertFalse(WebContext.current().isEncryptor());
        Assertions.assertNull(WebContext.current().getEncryptorFacade());
    }

    /**
     * 过滤器按"命中的配置 key"缓存 facade：同一 key 只构建一次（facadeFactory.apply 内部含 RSA 解析，是这条链路里最贵的部分）。
     */
    @Test
    public void test_facade_cached_by_matched_config_key() throws Exception {
        CryptoConfig uriConfig = new CryptoConfig();
        Map<String, CryptoConfig> cryptoConfig = new LinkedHashMap<>();
        cryptoConfig.put("^/test/hello.*", uriConfig);

        WebEncryptorConfig config = new WebEncryptorConfig();
        config.setCryptoConfig(cryptoConfig);

        CountingFacadeFactory factory = new CountingFacadeFactory();
        EncryptorWebFilter filter = new EncryptorWebFilter(config, factory);

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

    private static EncryptorFacade runAndCapture(EncryptorWebFilter filter, String uri) throws Exception {
        final EncryptorFacade[] captured = new EncryptorFacade[1];
        // 在 chain 内部读 facade：过滤器在 finally 里会 WebContext.clear()
        FilterChain chain = (req, res) -> captured[0] = WebContext.current().getEncryptorFacade();
        filter.doFilterInternal(new MockHttpServletRequest("GET", uri), new MockHttpServletResponse(), chain);
        return captured[0];
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
            return new EncryptorFacade(null, null, null, null);
        }

        int count() {
            return applyCount.get();
        }
    }
}
