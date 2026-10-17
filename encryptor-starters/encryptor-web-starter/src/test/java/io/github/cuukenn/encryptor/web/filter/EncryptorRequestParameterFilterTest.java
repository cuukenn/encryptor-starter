package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * v2 参数视图过滤器：只装 WebContext.parameters；链后清理 ThreadLocal。
 *
 * @author changgg
 */
class EncryptorRequestParameterFilterTest {
    private final EncryptorRequestParameterFilter filter = new EncryptorRequestParameterFilter();
    private final MockHttpServletResponse response = new MockHttpServletResponse();

    @AfterEach
    void tearDown() {
        WebContext.clear();
    }

    @Test
    void 解密后的参数覆写请求且链后清理上下文() throws Exception {
        WebContext ctx = WebContext.current();
        Map<String, String[]> parameters = new HashMap<>();
        parameters.put("a", new String[]{"1", "2"});
        parameters.put("b", new String[]{"3"});
        ctx.setReqEncryptor(true);
        ctx.setParameters(parameters);
        AtomicReference<ServletRequest> seen = new AtomicReference<>();
        FilterChain chain = (request, resp) -> {
            seen.set(request);
            assertThat(request.getParameter("a")).isEqualTo("1");
            assertThat(request.getParameterValues("a")).containsExactly("1", "2");
            assertThat(request.getParameter("b")).isEqualTo("3");
            assertThat(request.getParameterMap()).containsOnlyKeys("a", "b");
            assertThat(Collections.list(request.getParameterNames())).containsExactlyInAnyOrder("a", "b");
        };
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/a");
        filter.doFilter(request, response, chain);
        assertThat(seen.get()).isInstanceOf(javax.servlet.http.HttpServletRequestWrapper.class);
        // 链后 ThreadLocal 必须清空（线程池复用防泄漏）
        assertThat(WebContext.current().isReqEncryptor()).isFalse();
        assertThat(WebContext.current().getParameters()).isNull();
    }

    @Test
    void 未加密请求原样透传() throws Exception {
        AtomicReference<ServletRequest> seen = new AtomicReference<>();
        FilterChain chain = (request, resp) -> seen.set(request);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/plain");
        filter.doFilter(request, response, chain);
        assertThat(seen.get()).isSameAs(request);
    }
}
