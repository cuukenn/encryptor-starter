package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.config.CryptoConfig;
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
import java.util.LinkedHashMap;
import java.util.Map;

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
}
