package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;

/**
 * 解密后的参数视图（v2）：门面过滤器已一次性解密，这里只把 {@link WebContext#getParameters()} 装进请求包装器。
 *
 * @author changgg
 */
public class EncryptorRequestParameterFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 请求结束时清掉 ThreadLocal（线程池复用防泄漏）；响应过滤器(-3)嵌套在本过滤器(-11)内，
        // 链后加解密已全部完成，此时清理不影响响应改写
        try {
            doFilterWithParameters(request, response, filterChain);
        } finally {
            WebContext.clear();
        }
    }

    private void doFilterWithParameters(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        WebContext ctx = WebContext.current();
        if (!ctx.isReqEncryptor() || ctx.getParameters() == null) {
            filterChain.doFilter(request, response);
            return;
        }
        Map<String, String[]> parameters = ctx.getParameters();
        filterChain.doFilter(new HttpServletRequestWrapper(request) {
            @Override
            public Enumeration<String> getParameterNames() {
                return Collections.enumeration(parameters.keySet());
            }

            @Override
            public String[] getParameterValues(String name) {
                return parameters.get(name);
            }

            // getParameter / getParameterMap 必须一并覆写：只覆写上面两个的话，
            // 它们会回落到被包装的原始请求，同一个请求里出现"密文/明文"两个视图
            @Override
            public String getParameter(String name) {
                String[] values = parameters.get(name);
                return values == null || values.length == 0 ? null : values[0];
            }

            @Override
            public Map<String, String[]> getParameterMap() {
                return parameters;
            }
        }, response);
    }
}
