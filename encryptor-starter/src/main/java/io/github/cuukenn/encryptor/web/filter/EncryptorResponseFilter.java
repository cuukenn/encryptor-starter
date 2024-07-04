package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.web.converter.DefaultMessageConverter;
import io.github.cuukenn.encryptor.web.converter.MessageWriter;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * @author changgg
 */
public class EncryptorResponseFilter extends OncePerRequestFilter {
    private final List<MessageWriter> messageWriters;

    public EncryptorResponseFilter(List<MessageWriter> messageWriters) {
        this.messageWriters = messageWriters;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!WebContext.isResEncryptorEnable(response)) {
            filterChain.doFilter(request, response);
            return;
        }
        ContentCachingResponseWrapper cachingResponseWrapper = new ContentCachingResponseWrapper(response);
        filterChain.doFilter(request, cachingResponseWrapper);
        MessageWriter messageWriter = messageWriters.stream().filter(writer -> writer.canWrite(MediaType.valueOf(Optional.ofNullable(response.getContentType()).orElseGet(MediaType.APPLICATION_JSON::toString))))
                .findFirst()
                .orElseGet(DefaultMessageConverter::new);
        byte[] encryptedData = messageWriter.write().apply(request, response, cachingResponseWrapper.getContentAsByteArray());
        cachingResponseWrapper.resetBuffer();
        cachingResponseWrapper.getOutputStream().write(encryptedData);
        cachingResponseWrapper.copyBodyToResponse();
    }

    private EncryptorDataWrapper getEncrypt(byte[] content, String key) {
        return WebContext.current().getEncryptorFacade().encrypt(content, key);
    }
}
