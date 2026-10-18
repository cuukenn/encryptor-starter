package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.web.JweTestSupport;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * v2 门面过滤器：三载体解密 / 决策（黑名单、bypass、require-encrypted、kid 白名单）。
 *
 * @author changgg
 */
class EncryptorWebFilterTest {
    private final JweTestSupport support = new JweTestSupport();
    private final WebEncryptorConfig webConfig = new WebEncryptorConfig();
    private final EncryptorConfig protocolConfig = new EncryptorConfig();
    private final EncryptorWebFilter filter =
        new EncryptorWebFilter(webConfig, protocolConfig, support.protocol, support.protocol.runtime());
    private final AtomicBoolean chainExecuted = new AtomicBoolean(false);
    private final FilterChain chain = (request, response) -> chainExecuted.set(true);

    @AfterEach
    void tearDown() {
        WebContext.clear();
    }

    private void run(MockHttpServletRequest request, MockHttpServletResponse response) throws Exception {
        filter.doFilter(request, response, chain);
    }

    @Test
    void query载体解密成功() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/a");
        request.setParameter("jwe", support.seal("a=1&b=2", "/api/a", "GET"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(chainExecuted).isTrue();
        WebContext ctx = WebContext.current();
        assertThat(ctx.isReqEncryptor()).isTrue();
        assertThat(ctx.getCarrier()).isEqualTo(WebContext.Carrier.QUERY);
        assertThat(ctx.getJweContext()).isNotNull();
        assertThat(ctx.getParameters()).containsKey("a");
        assertThat(ctx.getParameters().get("a")).containsExactly("1");
        assertThat(ctx.getParameters().get("b")).containsExactly("2");
        assertThat(ctx.getParameters()).doesNotContainKey("jwe");
    }

    @Test
    void JSON载体解密成功() throws Exception {
        String plaintext = "{\"name\":\"alice\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/j");
        request.setContentType("application/json");
        request.setContent(("{\"jwe\":\"" + support.seal(plaintext, "/api/j", "POST") + "\"}").getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(chainExecuted).isTrue();
        WebContext ctx = WebContext.current();
        assertThat(ctx.getCarrier()).isEqualTo(WebContext.Carrier.JSON);
        assertThat(ctx.getBodyPlaintext()).isEqualTo(plaintext.getBytes(StandardCharsets.UTF_8));
        assertThat(ctx.getParameters()).isNull();
    }

    @Test
    void form载体解密成功() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/f");
        request.setContentType("application/x-www-form-urlencoded");
        request.setContent("jwe=x".getBytes(StandardCharsets.UTF_8));
        request.setParameter("jwe", support.seal("x=1&y=2", "/api/f", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(chainExecuted).isTrue();
        WebContext ctx = WebContext.current();
        assertThat(ctx.getCarrier()).isEqualTo(WebContext.Carrier.FORM);
        assertThat(ctx.getParameters()).containsKey("x");
        assertThat(ctx.getBodyPlaintext()).isEqualTo("x=1&y=2".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void 缺jwe回400且不进业务链() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/a");
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(chainExecuted).isFalse();
    }

    @Test
    void 超maxRequestSize按ContentLength回413() throws Exception {
        protocolConfig.setMaxRequestSize(64);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/j");
        request.setContentType("application/json");
        request.setContent(new byte[300]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(chainExecuted).isFalse();
    }

    @Test
    void 超maxRequestSize按有界读回413() throws Exception {
        protocolConfig.setMaxRequestSize(64);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/j") {
            @Override
            public long getContentLengthLong() {
                return -1L; // 模拟 chunked：无 Content-Length
            }
        };
        request.setContentType("application/json");
        request.setContent(new byte[300]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(chainExecuted).isFalse();
    }

    @Test
    void 空JSONbody回400不NPE() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/j");
        request.setContentType("application/json");
        request.setContent(new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(chainExecuted).isFalse();
    }

    @Test
    void bypassRequest透传() throws Exception {
        support.protocol.runtime().setBypass(true, false);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/a");
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(chainExecuted).isTrue();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(WebContext.current().isReqEncryptor()).isFalse();
    }

    @Test
    void skipUris透传() throws Exception {
        webConfig.getSkipUris().add("/api/open.*");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/open/public");
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(chainExecuted).isTrue();
        assertThat(WebContext.current().isReqEncryptor()).isFalse();
    }

    @Test
    void kid不在uri级白名单回400() throws Exception {
        webConfig.getCryptoConfig().put(".*", Arrays.asList("other-kid"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/a");
        request.setParameter("jwe", support.seal("a=1", "/api/a", "GET"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(chainExecuted).isFalse();
    }

    @Test
    void 篡改密文回400() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/a");
        request.setParameter("jwe", JweTestSupport.tamper(support.seal("a=1", "/api/a", "GET")));
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(chainExecuted).isFalse();
    }
}
