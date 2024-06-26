package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.web.kit.WebContext;
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

/**
 * 解密request body
 *
 * @author changgg
 */
public class EncryptorRequestBodyFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!WebContext.current().isReqEncryptor()) {
            filterChain.doFilter(request, response);
            return;
        }
        filterChain.doFilter(new ContentCachingRequestWrapper(request) {
            private InputStream newInputstream = null;

            @Override
            public ServletInputStream getInputStream() throws IOException {
                if (newInputstream == null) {
                    EncryptorDataWrapper dataWrapper = WebContext.current().getDataConverter().load(request, new String(getContentAsByteArray()));
                    byte[] decryptData = WebContext.current().getEncryptorFacade().decrypt(dataWrapper);
                    newInputstream = new BufferedInputStream(new ByteArrayInputStream(decryptData));
                    request.setAttribute(CoreEncryptorConstant.KEY, dataWrapper.getKey());
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
