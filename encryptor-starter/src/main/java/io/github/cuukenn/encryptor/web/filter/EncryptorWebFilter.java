package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.converter.DataConverterFactory;
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
    private final DataConverterFactory<CryptoConfig> dataConverterFactory;

    public EncryptorWebFilter(WebEncryptorConfig config, IEncryptorFacadeFactory<CryptoConfig> facadeFactory, DataConverterFactory<CryptoConfig> dataConverterFactory) {
        this.config = config;
        this.facadeFactory = facadeFactory;
        this.dataConverterFactory = dataConverterFactory;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
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
        WebContext.current().setEncryptor(true);
        String contentType = request.getHeader(HttpHeaders.CONTENT_TYPE);
        boolean isBlankReqContentType = contentType != null && StrKit.anyMatch(contentType, config.getBlackReqContentType());
        if (!isBlankReqContentType) {
            WebContext.current().setReqEncryptor(true);
        }
        WebContext.current().setConfig(config);
        String bestMatchStr = StrKit.getBestMatchStr(uri, config.getCryptoConfig().keySet());
        CryptoConfig cryptoConfig = bestMatchStr != null ? config.getCryptoConfig().get(uri) : null;
        WebContext.current().setEncryptorFacade(this.facadeFactory.apply(cryptoConfig));
        WebContext.current().setDataConverter(this.dataConverterFactory.apply(cryptoConfig));
        filterChain.doFilter(request, response);
    }
}
