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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * v2 响应过滤器：按真实链序（参数 → body → 响应 → 门面 → 业务）集成验证。
 * 响应过滤器 order -10 在门面过滤器 -3 外层，链后仍要读 WebContext —— 这正是 v1 的契约。
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

    @Test
    void 加密请求的响应被加密且可用请求CEK解开() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/a");
        request.setParameter("jwe", support.seal("a=1", "/api/a", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        runRealChain(request, response, (req, resp) -> {
            // 业务视角：参数已是明文
            assertThat(((HttpServletRequest) req).getParameter("a")).isEqualTo("1");
            cek.set(WebContext.current().getJweContext().cek());
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
        webConfig.setBlackResContentType(java.util.Collections.singletonList("application/octet-stream"));
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/dl");
        request.setParameter("jwe", support.seal("f=1", "/api/dl", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        runRealChain(request, response, (req, resp) -> {
            cek.set(WebContext.current().getJweContext().cek());
            ((HttpServletResponse) resp).setContentType("application/octet-stream");
            resp.getOutputStream().write(new byte[]{1, 2, 3});
        });
        assertThat(response.getContentType()).contains("application/octet-stream");
        assertThat(response.getContentAsByteArray()).containsExactly(1, 2, 3);
    }

    @Test
    void 响应超限回500且不发明文() throws Exception {
        protocolConfig.setMaxResponseSize(4);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/big");
        request.setParameter("jwe", support.seal("x=1", "/api/big", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        runRealChain(request, response, (req, resp) -> {
            byte[] big = new byte[16];
            resp.getOutputStream().write(big);
        });
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        assertThat(response.getContentAsByteArray()).isEmpty();
    }
}
