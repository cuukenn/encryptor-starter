package io.github.cuukenn.encryptor.web.filter;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;
import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.web.JweTestSupport;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.util.StreamUtils;

import jakarta.servlet.FilterChain;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.slf4j.LoggerFactory.getLogger;

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
    void 启动日志打印skip名单与流式风险() {
        Logger logger = (Logger) getLogger(EncryptorWebFilter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        WebEncryptorConfig config = new WebEncryptorConfig();
        config.getSkipResContentType().clear();
        try {
            new EncryptorWebFilter(config, protocolConfig, support.protocol, support.protocol.runtime());
        } finally {
            logger.detachAppender(appender);
        }
        assertThat(appender.list).anyMatch(e -> e.getLevel() == Level.INFO
            && e.getFormattedMessage().contains("skip-res-content-type"));
        assertThat(appender.list).anyMatch(e -> e.getLevel() == Level.WARN
            && e.getFormattedMessage().contains("整体缓冲"));
    }

    @Test
    void skip名单含eventStream时告警明示不加密() {
        WebEncryptorConfig config = new WebEncryptorConfig();
        config.getSkipResContentType().add("text/event-stream");
        Logger logger = (Logger) getLogger(EncryptorWebFilter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            new EncryptorWebFilter(config, protocolConfig, support.protocol, support.protocol.runtime());
        } finally {
            logger.detachAppender(appender);
        }
        assertThat(appender.list).anyMatch(e -> e.getLevel() == Level.WARN
            && e.getFormattedMessage().contains("不加密"));
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
    void 超大ContentLength不会按声明值预分配() throws Exception {
        protocolConfig.setMaxRequestSize(4L * 1024 * 1024 * 1024);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/j") {
            @Override
            public long getContentLengthLong() {
                return 3L * 1024 * 1024 * 1024;
            }
        };
        request.setContentType("application/json");
        request.setContent("{}".getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();

        run(request, response);

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(chainExecuted).isFalse();
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
    void 失败时traceId同时出现在响应头与日志() throws Exception {
        Logger logger = (Logger) LoggerFactory.getLogger(EncryptorWebFilter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/j");
            MockHttpServletResponse response = new MockHttpServletResponse();
            run(request, response);

            String trace = response.getHeader(EncryptorResponseFilter.TRACE_HEADER);
            assertThat(trace).isNotBlank();
            assertThat(appender.list).anySatisfy(event ->
                assertThat(event.getFormattedMessage()).contains(trace));
        } finally {
            logger.detachAppender(appender);
        }
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
    void chunked表单请求直接413且不调用getParameter() throws Exception {
        protocolConfig.setMaxRequestSize(1024);
        AtomicBoolean parameterAccessed = new AtomicBoolean(false);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/f") {
            @Override
            public long getContentLengthLong() {
                return -1L; // chunked：容器无法预判大小
            }

            @Override
            public String getParameter(String name) {
                parameterAccessed.set(true);
                return super.getParameter(name);
            }
        };
        request.setContentType("application/x-www-form-urlencoded");
        request.setContent("jwe=x".getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(parameterAccessed).isFalse();
        assertThat(chainExecuted).isFalse();
    }

    @Test
    void 表单超maxRequestSize按ContentLength回413且不解析参数() throws Exception {
        protocolConfig.setMaxRequestSize(64);
        AtomicBoolean parameterAccessed = new AtomicBoolean(false);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/f") {
            @Override
            public long getContentLengthLong() {
                return 300L;
            }

            @Override
            public String getParameter(String name) {
                parameterAccessed.set(true);
                return super.getParameter(name);
            }
        };
        request.setContentType("application/x-www-form-urlencoded");
        request.setContent(new byte[300]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(chainExecuted).isFalse();
        assertThat(parameterAccessed).isFalse();
    }

    @Test
    void 空JSONbody且requireEncryptedFalse时透传() throws Exception {
        protocolConfig.setRequireEncrypted(false);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/j");
        request.setContentType("application/json");
        request.setContent(new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(chainExecuted).isTrue();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(WebContext.current().isReqEncryptor()).isFalse();
    }

    @Test
    void 非空JSON明文透传时下游仍能读到原始body() throws Exception {
        protocolConfig.setRequireEncrypted(false);
        byte[] plaintext = "{\"foo\":1}".getBytes(StandardCharsets.UTF_8);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/j");
        request.setContentType("application/json");
        request.setContent(plaintext);
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> seen = new AtomicReference<>();
        filter.doFilter(request, response, (req, res) ->
            seen.set(StreamUtils.copyToString(req.getInputStream(), StandardCharsets.UTF_8)));
        assertThat(seen.get()).isEqualTo("{\"foo\":1}");
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

    @Test
    void contextPath部署下uri级白名单按去前缀路径匹配() throws Exception {
        webConfig.getCryptoConfig().put("/test/hello", Arrays.asList(JweTestSupport.KID));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/test/hello");
        request.setContextPath("/app");
        request.setParameter("jwe", support.seal("a=1", "/app/test/hello", "GET"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(chainExecuted).isTrue();
    }

    @Test
    void contextPath部署下白名单kid不符被拒() throws Exception {
        webConfig.getCryptoConfig().put("/test/hello", Arrays.asList("other-kid"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/test/hello");
        request.setContextPath("/app");
        request.setParameter("jwe", support.seal("a=1", "/app/test/hello", "GET"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(chainExecuted).isFalse();
    }

    @Test
    void contextPath部署下skipUris按去前缀路径命中() throws Exception {
        webConfig.getSkipUris().add("/test/skip.*");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/test/skip");
        request.setContextPath("/app");
        MockHttpServletResponse response = new MockHttpServletResponse();
        run(request, response);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(chainExecuted).isTrue();
        assertThat(WebContext.current().isReqEncryptor()).isFalse();
    }
}
