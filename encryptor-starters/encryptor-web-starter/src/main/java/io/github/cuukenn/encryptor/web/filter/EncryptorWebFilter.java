package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.facade.IEncryptorFacadeFactory;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author changgg
 */
public class EncryptorWebFilter extends OncePerRequestFilter {
    private final WebEncryptorConfig config;
    private final IEncryptorFacadeFactory<CryptoConfig> facadeFactory;

    public EncryptorWebFilter(WebEncryptorConfig config, IEncryptorFacadeFactory<CryptoConfig> facadeFactory) {
        this.config = config;
        this.facadeFactory = facadeFactory;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            final String uri = request.getRequestURI();
            boolean isBlankUri = StrKit.anyMatch(uri, config.getBlackUris());
            if (isBlankUri) {
                filterChain.doFilter(request, response);
                return;
            }
            boolean isBlankMethod = StrKit.anyMatch(request.getMethod(), config.getBlackMethods());
            if (isBlankMethod) {
                filterChain.doFilter(request, response);
                return;
            }
            WebContext context = WebContext.current();
            context.setEncryptor(true);
            String contentType = request.getHeader(HttpHeaders.CONTENT_TYPE);
            boolean isBlankReqContentType = contentType != null && StrKit.anyMatch(contentType, config.getBlackReqContentType());
            if (!isBlankReqContentType) {
                context.setReqEncryptor(true);
            }
            context.setConfig(config);
            String bestMatchStr = StrKit.getBestMatchStr(uri, config.getCryptoConfig().keySet());
            // 必须用命中的正则 key 取值：用 uri 取值会让 uri 级 crypto-config 永远匹配不到
            CryptoConfig cryptoConfig = bestMatchStr != null ? config.getCryptoConfig().get(bestMatchStr) : null;
            context.setEncryptorFacade(this.facadeFactory.apply(cryptoConfig));
            filterChain.doFilter(request, response);
        } finally {
            // 请求结束必须清理上下文：Servlet 线程池会复用线程，
            // 否则上一个请求的 EncryptorFacade / config / 标志位会泄漏到下一个请求
            WebContext.clear();
        }
    }
}
