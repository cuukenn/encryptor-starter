package io.github.cuukenn.encryptor.web.discovery;

import io.github.cuukenn.encryptor.config.DiscoveryConfig;
import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.JwksDocument;
import io.github.cuukenn.encryptor.jose.ServerKeyStore;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JWKS 只读发现端点：{@code GET ${discovery.path}} → 只含公钥的 JWKS（免加密、可缓存、支持 304）。
 *
 * <p>注册在最外层（先于加密过滤器），命中时直接写出响应不放行链；enable=false 或路径不匹配时原样放行。</p>
 *
 * @author changgg
 */
public class JwksEndpointFilter extends OncePerRequestFilter {

    private final String path;
    private final boolean enable;
    private final String cacheControl;
    /** 密钥库不可变 ⇒ JWKS 与 ETag 在构造期定型（换 active-kid = 换密钥库 = 换实例）。 */
    private final String body;
    private final String etag;

    public JwksEndpointFilter(ServerKeyStore keys, DiscoveryConfig discovery) {
        this.path = discovery.getPath();
        this.enable = discovery.isEnable();
        this.cacheControl = "public, max-age=" + discovery.getCacheMaxAgeSeconds();
        JwksDocument document = new JwksDocument(keys);
        this.body = document.body();
        this.etag = document.etag();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!enable || !"GET".equals(request.getMethod())
            || !path.equals(ContextAad.canonicalPath(request.getRequestURI(), request.getContextPath()))) {
            filterChain.doFilter(request, response);
            return;
        }
        response.setHeader("ETag", etag);
        response.setHeader("Cache-Control", cacheControl);
        if (etag.equals(request.getHeader("If-None-Match"))) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(body);
    }
}
