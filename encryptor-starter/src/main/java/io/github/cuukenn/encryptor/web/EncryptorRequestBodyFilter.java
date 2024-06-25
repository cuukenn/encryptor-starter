package io.github.cuukenn.encryptor.web;

import io.github.cuukenn.encryptor.converter.DataConverter;
import io.github.cuukenn.encryptor.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * 解密request body
 *
 * @author changgg
 */
public class EncryptorRequestBodyFilter extends OncePerRequestFilter {
    private final EncryptorFacade encryptorEncoder;
    private final DataConverter dataConverter;

    public EncryptorRequestBodyFilter(EncryptorFacade encryptorEncoder, DataConverter dataConverter) {
        this.encryptorEncoder = encryptorEncoder;
        this.dataConverter = dataConverter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        filterChain.doFilter(new ContentCachingRequestWrapper(request) {
            private InputStream newInputstream = null;

            @Override
            public ServletInputStream getInputStream() throws IOException {
                if (newInputstream == null) {
                    EncryptorDataWrapper dataWrapper = dataConverter.load(request, new String(getContentAsByteArray(), StandardCharsets.UTF_8));
                    String decryptData = encryptorEncoder.decrypt(dataWrapper);
                    newInputstream = new BufferedInputStream(new ByteArrayInputStream(decryptData.getBytes(StandardCharsets.UTF_8)));
                    request.setAttribute(EncryptorConstant.KEY, dataWrapper.getKey());
                }
                return new ServletInputStream() {
                    @Override
                    public int read() throws IOException {
                        return newInputstream.read();
                    }

                    @Override
                    public boolean isFinished() {
                        return false;
                    }

                    @Override
                    public boolean isReady() {
                        return false;
                    }

                    @Override
                    public void setReadListener(ReadListener listener) {
                    }
                };
            }
        }, response);
    }
}
