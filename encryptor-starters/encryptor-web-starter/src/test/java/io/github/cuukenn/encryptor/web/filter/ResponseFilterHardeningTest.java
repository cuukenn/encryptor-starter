package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import io.github.cuukenn.encryptor.web.SmJweTestSupport;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * 评审修复回归（web 侧）：国密响应 enc 显式传递、运行期 bypass 生效、响应有界缓冲、
 * Content-Encoding 清理、失败带 traceId。
 *
 * @author changgg
 */
class ResponseFilterHardeningTest {
    private final SmJweTestSupport sm = new SmJweTestSupport();
    private final WebEncryptorConfig web = new WebEncryptorConfig();
    private final EncryptorConfig config = new EncryptorConfig();

    @AfterEach
    void tearDown() {
        WebContext.clear();
    }

    private void runChain(MockHttpServletRequest request, MockHttpServletResponse response,
                          FilterChain business) throws Exception {
        EncryptorWebFilter webFilter = new EncryptorWebFilter(web, config, sm.protocol, sm.protocol.runtime());
        EncryptorRequestParameterFilter parameterFilter = new EncryptorRequestParameterFilter();
        EncryptorRequestBodyFilter bodyFilter = new EncryptorRequestBodyFilter();
        EncryptorResponseFilter responseFilter =
            new EncryptorResponseFilter(config, sm.protocol, sm.protocol.runtime());
        webFilter.doFilter(request, response, (a, b) ->
            parameterFilter.doFilter(a, b, (c, d) ->
                bodyFilter.doFilter(c, d, (e, f) -> responseFilter.doFilter(e, f, business))));
    }

    @Test
    void 国密请求的响应仍用SM4GCM封装() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/a");
        MockHttpServletResponse response = new MockHttpServletResponse();
        SmJweTestSupport.Sealed sealed = sm.seal("a=1", "/api/a", "POST");
        request.setParameter("jwe", sealed.compact);
        runChain(request, response, (req, res) -> {
            res.setContentType("application/json");
            res.getOutputStream().write("{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
        });
        String payload = response.getContentAsString();
        assertTrue(payload.contains("\"jwe\""), "响应应是 jwe 信封: " + payload);
        assertTrue(SmJweTestSupport.responseHeaderJson(payload).contains("SM4-GCM"),
            "响应 enc 必须与请求协商的 enc 一致: " + SmJweTestSupport.responseHeaderJson(payload));
        assertEquals("{\"ok\":true}",
            new String(SmJweTestSupport.sm4DecryptResponse(payload, sealed.cek), StandardCharsets.UTF_8));
    }

    @Test
    void 运行期bypass响应后不包装() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/a");
        MockHttpServletResponse response = new MockHttpServletResponse();
        EncryptorRuntime runtime = sm.protocol.runtime();
        runtime.setBypass(false, true);
        try {
            request.setParameter("jwe", sm.seal("a=1", "/api/a", "POST").compact);
            runChain(request, response, (req, res) -> {
                res.setContentType("text/plain");
                res.getOutputStream().write("plain".getBytes(StandardCharsets.UTF_8));
            });
            assertEquals("plain", response.getContentAsString(), "bypass.response=true 时不得包装响应");
        } finally {
            runtime.setBypass(false, false);
        }
    }

    @Test
    void 响应超限时有界缓冲并回500() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/a");
        MockHttpServletResponse response = new MockHttpServletResponse();
        config.setMaxResponseSize(4);
        try {
            request.setParameter("jwe", sm.seal("a=1", "/api/a", "POST").compact);
            runChain(request, response, (req, res) -> {
                res.setContentType("application/json");
                res.getOutputStream().write("0123456789abcdef".getBytes(StandardCharsets.UTF_8));
            });
            assertEquals(500, response.getStatus());
            assertEquals("", response.getContentAsString(), "超限不得把明文发出去");
        } finally {
            config.setMaxResponseSize(4194304L);
        }
    }

    @Test
    void 下游gzip响应封装后不残留ContentEncoding() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/a");
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setParameter("jwe", sm.seal("a=1", "/api/a", "POST").compact);
        runChain(request, response, (req, res) -> {
            res.setContentType("application/json");
            ((HttpServletResponse) res).setHeader("Content-Encoding", "gzip");
            res.getOutputStream().write("{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
        });
        String encoding = response.getHeader("Content-Encoding");
        assertTrue(encoding == null || "identity".equalsIgnoreCase(encoding),
            "body 已换成 JWE JSON，Content-Encoding 不得仍是 gzip，否则客户端按 gzip 解得乱码: " + encoding);
        assertTrue(response.getContentAsString().contains("\"jwe\""));
    }

    @Test
    void 报文非法时失败响应带traceId且上下文被清理() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/a");
        MockHttpServletResponse response = new MockHttpServletResponse();
        runChain(request, response, (req, res) -> fail("非法报文不得进入业务链"));
        assertEquals(400, response.getStatus());
        assertNotNull(response.getHeader("X-Encryptor-Trace"), "失败响应应带 traceId 便于对日志");
        assertNull(WebContext.current().getJweContext(), "提前失败也必须清理上下文");
    }
}
