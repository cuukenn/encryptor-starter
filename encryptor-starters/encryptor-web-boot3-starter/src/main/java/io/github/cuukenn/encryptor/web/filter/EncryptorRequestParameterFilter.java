package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.nio.charset.StandardCharsets;
import java.net.URLDecoder;
import java.io.UnsupportedEncodingException;
import io.github.cuukenn.encryptor.constant.EncryptorConstant;
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
        // 请求结束时清掉 ThreadLocal（线程池复用防泄漏）。链序契约由 WebEncryptorConfiguration
        // 的启动期校验保证（本过滤器在响应过滤器之外、门面之内），链后加解密已完成，清理不影响响应改写。
        // clear 用异步感知重载：响应未包装（旁路/透传）的异步请求，异步处理器可能还在读明文，
        // 不能在 finally 里提前清零（加密路径的所有权移交不受影响）。
        try {
            doFilterWithParameters(request, response, filterChain);
        } finally {
            WebContext.clear(request);
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

            // 参数视图已隐藏 jwe，query string 也必须一致：否则日志/self-link/CDN 缓存键
            // 仍会带上整段密文（体积是明文的 1.4 倍）。
            @Override
            public String getQueryString() {
                return withoutJwe(super.getQueryString());
            }
        }, response);
    }

    private static String withoutJwe(String query) {
        if (query == null || query.isEmpty()) {
            return query;
        }
        StringBuilder kept = new StringBuilder(query.length());
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String rawName = eq < 0 ? pair : pair.substring(0, eq);
            if (EncryptorConstant.JWE_PARAM.equals(rawName) || EncryptorConstant.JWE_PARAM.equals(decode(rawName))) {
                continue;
            }
            if (kept.length() > 0) {
                kept.append('&');
            }
            kept.append(pair);
        }
        return kept.length() == 0 ? null : kept.toString();
    }

    private static String decode(String name) {
        try {
            return URLDecoder.decode(name, StandardCharsets.UTF_8.name());
        } catch (RuntimeException | UnsupportedEncodingException e) {
            return name;
        }
    }
}
