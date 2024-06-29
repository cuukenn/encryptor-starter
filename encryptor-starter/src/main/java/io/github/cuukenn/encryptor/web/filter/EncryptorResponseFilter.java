package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author changgg
 */
public class EncryptorResponseFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!WebContext.isResEncryptorEnable(response)) {
            filterChain.doFilter(request, response);
            return;
        }
        ContentCachingResponseWrapper cachingResponseWrapper = new ContentCachingResponseWrapper(response);
        filterChain.doFilter(request, cachingResponseWrapper);
        String key = (String) request.getAttribute(CoreEncryptorConstant.KEY);
        if (key == null) {
            return;
        }
        EncryptorDataWrapper encryptData = getEncrypt(cachingResponseWrapper.getContentAsByteArray(), key);
        WebContext.current().getDataConverter().post(cachingResponseWrapper, encryptData);
        cachingResponseWrapper.copyBodyToResponse();
    }

    private EncryptorDataWrapper getEncrypt(byte[] content, String key) {
        return WebContext.current().getEncryptorFacade().encrypt(content, key);
    }
}
