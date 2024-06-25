package io.github.cuukenn.encryptor.web;

import io.github.cuukenn.encryptor.converter.DataConverter;
import io.github.cuukenn.encryptor.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * @author changgg
 */
public class EncryptorResponseFilter extends OncePerRequestFilter {
    private final EncryptorFacade encryptorEncoder;
    private final DataConverter dataConverter;

    public EncryptorResponseFilter(EncryptorFacade encryptorEncoder, DataConverter dataConverter) {
        this.encryptorEncoder = encryptorEncoder;
        this.dataConverter = dataConverter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String key = (String) request.getAttribute(EncryptorConstant.KEY);
        if (key == null) {
            filterChain.doFilter(request, response);
            return;
        }
        ContentCachingResponseWrapper cachingResponseWrapper = new ContentCachingResponseWrapper(response);
        filterChain.doFilter(request, cachingResponseWrapper);
        EncryptorDataWrapper encryptData = getEncrypt(cachingResponseWrapper.getContentAsByteArray(), key);
        dataConverter.post(cachingResponseWrapper, encryptData);
        cachingResponseWrapper.copyBodyToResponse();
    }

    private EncryptorDataWrapper getEncrypt(byte[] content, String key) {
        return encryptorEncoder.encrypt(new String(content, StandardCharsets.UTF_8), key);
    }
}
