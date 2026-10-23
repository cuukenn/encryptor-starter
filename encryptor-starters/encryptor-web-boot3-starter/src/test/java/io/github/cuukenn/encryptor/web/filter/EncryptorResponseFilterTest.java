package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.web.JweTestSupport;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockAsyncContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * v2 响应过滤器：按真实链序（门面 → 参数 → body → 响应 → 业务）集成验证。
 * 响应过滤器在门面**内层**，业务写完响应后才回加密，此时仍要读 {@code WebContext} 里的同一把 CEK。
 * （把链序钉死的是 {@link FilterChainOrderTest}，本类只验响应过滤器自身行为。）
 *
 * @author changgg
 */
class EncryptorResponseFilterTest {
    private final JweTestSupport support = new JweTestSupport();
    private final WebEncryptorConfig webConfig = new WebEncryptorConfig();
    private final EncryptorConfig protocolConfig = new EncryptorConfig();
    private final EncryptorRequestParameterFilter parameterFilter = new EncryptorRequestParameterFilter();
    private final EncryptorRequestBodyFilter bodyFilter = new EncryptorRequestBodyFilter();
    private final EncryptorResponseFilter responseFilter = new EncryptorResponseFilter(protocolConfig, support.protocol);
    private final EncryptorWebFilter webFilter =
        new EncryptorWebFilter(webConfig, protocolConfig, support.protocol, support.protocol.runtime());

    @AfterEach
    void tearDown() {
        WebContext.clear();
    }

    /**
     * 链序与生产一致：门面(-12 决策+解密) → 参数(-11) → body(-10) → 响应(-3) → 业务。
     */
    private void runRealChain(MockHttpServletRequest request, MockHttpServletResponse response, FilterChain business) throws Exception {
        webFilter.doFilter(request, response, (req1, resp1) ->
            parameterFilter.doFilter(req1, resp1, (req2, resp2) ->
                bodyFilter.doFilter(req2, resp2, (req3, resp3) ->
                    responseFilter.doFilter(req3, resp3, business))));
    }

    private MockHttpServletRequest encryptedRequest(String method, String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, uri);
        request.setParameter("jwe", support.seal("a=1", uri, method));
        return request;
    }

    /** 表单载体也会把解密后的 body 放进 WebContext，用于验证异步交接时的所有权。 */
    private MockHttpServletRequest encryptedFormRequest(String method, String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, uri);
        request.setContentType("application/x-www-form-urlencoded");
        // 真实表单 POST 一定带 body（jwe=...）；不设置 content 的裸参数会让 Content-Length=-1，
        // 被"chunked 表单"防护拦成 413。
        request.setContent("jwe=x".getBytes(StandardCharsets.UTF_8));
        request.setParameter("jwe", support.seal("a=1", uri, method));
        return request;
    }

    /** 客户端视角持有自己的 CEK；服务端上下文在请求结束后会被清零，测试必须先复制。 */
    private static byte[] copyCek() {
        byte[] cek = WebContext.current().getJweContext().cek();
        return Arrays.copyOf(cek, cek.length);
    }

    @Test
    void 响应204不加密也不带body() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        runRealChain(encryptedRequest("POST", "/api/a"), response,
            (req, resp) -> ((HttpServletResponse) resp).setStatus(204));

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(response.getContentAsByteArray()).isEmpty();
        assertThat(response.getContentType()).isNotEqualTo("application/json");
    }

    @Test
    void 响应304不加密也不带body() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        runRealChain(encryptedRequest("POST", "/api/a"), response,
            (req, resp) -> ((HttpServletResponse) resp).setStatus(304));

        assertThat(response.getStatus()).isEqualTo(304);
        assertThat(response.getContentAsByteArray()).isEmpty();
    }

    @Test
    void 响应200空body封装为空明文JWE() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        runRealChain(encryptedRequest("POST", "/api/a"), response, (req, resp) -> cek.set(copyCek()));

        String payload = response.getContentAsString();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(payload).contains("\"jwe\"");
        assertThat(JweTestSupport.decryptResponse(payload, cek.get())).isEmpty();
    }

    @Test
    void HEAD响应不加密也不带body() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        runRealChain(encryptedRequest("HEAD", "/api/a"), response,
            (req, resp) -> resp.getWriter().write("should-not-be-encrypted"));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsByteArray()).isEmpty();
    }

    @Test
    void sendError不泄露明文且消息随JWE返回() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        runRealChain(encryptedRequest("POST", "/api/a"), response, (req, resp) -> {
            cek.set(copyCek());
            ((HttpServletResponse) resp).setContentType("application/json");
            resp.getWriter().write("{\"secret\":\"plain\"}");
            ((HttpServletResponse) resp).sendError(400, "bad-request");
        });

        String payload = response.getContentAsString();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(payload).contains("\"jwe\"");
        assertThat(payload).doesNotContain("secret");
        assertThat(new String(JweTestSupport.decryptResponse(payload, cek.get()), StandardCharsets.UTF_8))
            .isEqualTo("bad-request");
    }

    @Test
    void sendError消息不受已有writer字符集影响() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        runRealChain(encryptedRequest("POST", "/api/a"), response, (req, resp) -> {
            cek.set(copyCek());
            resp.setCharacterEncoding("ISO-8859-1");
            resp.getWriter().write("before-error");
            ((HttpServletResponse) resp).sendError(400, "中文错误");
        });

        String payload = response.getContentAsString();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(new String(JweTestSupport.decryptResponse(payload, cek.get()), StandardCharsets.UTF_8))
            .isEqualTo("中文错误");
    }

    @Test
    void 已提交响应sendError抛IllegalStateException() {
        MockHttpServletResponse raw = new MockHttpServletResponse();
        raw.setCommitted(true);
        BoundedContentCachingResponseWrapper wrapper = new BoundedContentCachingResponseWrapper(raw, 1024);

        assertThrows(IllegalStateException.class, () -> wrapper.sendError(400, "late"));
    }

    @Test
    void 已提交响应sendRedirect抛IllegalStateException() {
        MockHttpServletResponse raw = new MockHttpServletResponse();
        raw.setCommitted(true);
        BoundedContentCachingResponseWrapper wrapper = new BoundedContentCachingResponseWrapper(raw, 1024);

        assertThrows(IllegalStateException.class, () -> wrapper.sendRedirect("/late"));
    }

    @Test
    void sendRedirect不泄露已写入的明文() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        runRealChain(encryptedRequest("POST", "/api/a"), response, (req, resp) -> {
            resp.getWriter().write("secret-before-redirect");
            ((HttpServletResponse) resp).sendRedirect("/login");
        });

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getHeader("Location")).isEqualTo("/login");
        assertThat(response.getContentAsByteArray()).isEmpty();
    }

    @Test
    void 接近上限的响应仍返回完整JWE() throws Exception {
        protocolConfig.setMaxResponseSize(1000);
        byte[] body = new byte[800];
        java.util.Arrays.fill(body, (byte) 'a');
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/near-limit");
        request.setParameter("jwe", support.seal("a=1", "/api/near-limit", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        runRealChain(request, response, (req, resp) -> {
            cek.set(copyCek());
            ((HttpServletResponse) resp).setContentType("application/json");
            resp.getOutputStream().write(body);
        });

        String payload = response.getContentAsString();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(payload).contains("\"jwe\"");
        assertThat(JweTestSupport.decryptResponse(payload, cek.get())).isEqualTo(body);
    }

    @Test
    void 接近上限的sendError仍返回原状态与加密消息() throws Exception {
        protocolConfig.setMaxResponseSize(1000);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/near-limit-error");
        request.setParameter("jwe", support.seal("a=1", "/api/near-limit-error", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        runRealChain(request, response, (req, resp) -> {
            cek.set(copyCek());
            char[] filler = new char[990];
            java.util.Arrays.fill(filler, 'a');
            resp.getWriter().write(filler);
            ((HttpServletResponse) resp).sendError(400, "bad-request");
        });

        String payload = response.getContentAsString();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(payload).contains("\"jwe\"");
        assertThat(new String(JweTestSupport.decryptResponse(payload, cek.get()), StandardCharsets.UTF_8))
            .isEqualTo("bad-request");
    }

    @Test
    void 带body的302响应仍加密() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/redirect-body");
        request.setParameter("jwe", support.seal("a=1", "/api/redirect-body", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        runRealChain(request, response, (req, resp) -> {
            cek.set(copyCek());
            ((HttpServletResponse) resp).setStatus(302);
            resp.getWriter().write("{\"ok\":true}");
        });

        String payload = response.getContentAsString();
        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(payload).contains("\"jwe\"");
        assertThat(JweTestSupport.decryptResponse(payload, cek.get()))
            .isEqualTo("{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void reset后写入按新内容重新计上限() throws Exception {
        protocolConfig.setMaxResponseSize(1000);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/reset");
        request.setParameter("jwe", support.seal("a=1", "/api/reset", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        runRealChain(request, response, (req, resp) -> {
            cek.set(copyCek());
            char[] discarded = new char[800];
            java.util.Arrays.fill(discarded, 'a');
            resp.getWriter().write(discarded);
            ((HttpServletResponse) resp).reset();
            char[] kept = new char[300];
            java.util.Arrays.fill(kept, 'b');
            resp.getWriter().write(kept);
        });

        String payload = response.getContentAsString();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(payload).contains("\"jwe\"");
        byte[] plaintext = JweTestSupport.decryptResponse(payload, cek.get());
        assertThat(plaintext).hasSize(300);
        for (byte b : plaintext) {
            assertThat(b).isEqualTo((byte) 'b');
        }
    }

    @Test
    void 带body的302超限时回500且不发明文() throws Exception {
        protocolConfig.setMaxResponseSize(4);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/redirect-big");
        request.setParameter("jwe", support.seal("a=1", "/api/redirect-big", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        runRealChain(request, response, (req, resp) -> {
            ((HttpServletResponse) resp).setStatus(302);
            resp.getOutputStream().write(new byte[16]);
        });

        assertThat(response.getStatus()).isEqualTo(500);
        assertThat(response.getContentAsByteArray()).isEmpty();
    }

    @Test
    void 业务抛异常时回500且不泄露明文() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/boom");
        request.setParameter("jwe", support.seal("a=1", "/api/boom", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        runRealChain(request, response, (req, resp) -> {
            resp.getWriter().write("secret-before-exception");
            throw new IllegalStateException("boom");
        });

        assertThat(response.getStatus()).isEqualTo(500);
        assertThat(response.getContentAsString()).doesNotContain("secret");
        assertThat(response.getContentAsByteArray()).isEmpty();
    }

    @Test
    void 加密请求的响应被加密且可用请求CEK解开() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/a");
        request.setParameter("jwe", support.seal("a=1", "/api/a", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        runRealChain(request, response, (req, resp) -> {
            // 业务视角：参数已是明文
            assertThat(((HttpServletRequest) req).getParameter("a")).isEqualTo("1");
            cek.set(copyCek());
            ((HttpServletResponse) resp).setContentType("application/json");
            resp.getWriter().write("{\"ok\":true}");
        });
        String payload = response.getContentAsString();
        assertThat(response.getContentType()).contains("application/json");
        assertThat(payload).contains("\"jwe\"");
        assertThat(JweTestSupport.decryptResponse(payload, cek.get()))
            .isEqualTo("{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
        // 响应必须是 dir=res（用请求 CEK 直接加密）
        assertThat(JweTestSupport.responseHeaderJson(payload)).contains("\"dir\":\"res\"");
    }

    @Test
    void 明文请求不包装不缓冲() throws Exception {
        protocolConfig.setRequireEncrypted(false);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/plain");
        MockHttpServletResponse response = new MockHttpServletResponse();
        runRealChain(request, response, (req, resp) -> resp.getWriter().write("plain"));
        assertThat(response.getContentAsString()).isEqualTo("plain");
    }

    @Test
    void 黑名单响应contentType原样放行() throws Exception {
        webConfig.setSkipResContentType(java.util.Collections.singletonList("application/octet-stream"));
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/dl");
        request.setParameter("jwe", support.seal("f=1", "/api/dl", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        runRealChain(request, response, (req, resp) -> {
            cek.set(copyCek());
            ((HttpServletResponse) resp).setContentType("application/octet-stream");
            resp.getOutputStream().write(new byte[]{1, 2, 3});
        });
        assertThat(response.getContentType()).contains("application/octet-stream");
        assertThat(response.getContentAsByteArray()).containsExactly(1, 2, 3);
    }

    @Test
    void 异步错误回空500且不发明文() throws Exception {
        MockHttpServletRequest request = encryptedRequest("POST", "/api/async-error");
        request.setAsyncSupported(true);
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<AsyncContext> async = new AtomicReference<>();

        runRealChain(request, response, (req, resp) -> {
            copyCek();
            async.set(req.startAsync());
            resp.getWriter().write("secret");
        });

        AsyncListener listener = ((MockAsyncContext) request.getAsyncContext()).getListeners().get(0);
        listener.onError(new AsyncEvent(async.get()));

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        assertThat(response.getContentAsByteArray()).isEmpty();
    }

    @Test
    void 链返回后异步完成的响应仍会加密() throws Exception {
        MockHttpServletRequest request = encryptedRequest("POST", "/api/async");
        request.setAsyncSupported(true);
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        AtomicReference<AsyncContext> async = new AtomicReference<>();
        AtomicReference<HttpServletResponse> asyncResponse = new AtomicReference<>();

        runRealChain(request, response, (req, resp) -> {
            cek.set(copyCek());
            asyncResponse.set((HttpServletResponse) resp);
            async.set(req.startAsync());
        });

        // 模拟真实异步：业务线程在过滤器链返回后才写响应并 complete。
        asyncResponse.get().setContentType("application/json;charset=UTF-8");
        asyncResponse.get().getWriter().write("{\"ok\":true}");
        async.get().complete();

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(response.getContentType()).startsWith("application/json");
        byte[] plain = JweTestSupport.decryptResponse(response.getContentAsString(), cek.get());
        assertThat(new String(plain, StandardCharsets.UTF_8)).isEqualTo("{\"ok\":true}");
    }

    @Test
    void 异步交接后请求明文保留到完成后才清零() throws Exception {
        MockHttpServletRequest request = encryptedFormRequest("POST", "/api/async-body");
        request.setAsyncSupported(true);
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> body = new AtomicReference<>();
        AtomicReference<AsyncContext> async = new AtomicReference<>();
        AtomicReference<HttpServletResponse> asyncResponse = new AtomicReference<>();

        runRealChain(request, response, (req, resp) -> {
            body.set(WebContext.current().getBodyPlaintext());
            asyncResponse.set((HttpServletResponse) resp);
            async.set(req.startAsync());
        });

        // 参数过滤器 finally 已经执行过一轮；异步处理器仍应能读到原始明文。
        assertThat(new String(body.get(), StandardCharsets.UTF_8)).isEqualTo("a=1");

        asyncResponse.get().setContentType("application/json");
        asyncResponse.get().getWriter().write("{}");
        async.get().complete();

        assertThat(body.get()).containsOnly((byte) 0);
    }
}
