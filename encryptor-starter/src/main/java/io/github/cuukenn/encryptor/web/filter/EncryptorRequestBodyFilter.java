package io.github.cuukenn.encryptor.web.filter;

import cn.hutool.core.io.IoUtil;
import cn.hutool.http.HttpUtil;
import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

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
        InputStream newInputstream;
        byte[] bytes = IoUtil.readBytes(request.getInputStream());
        if (bytes != null && bytes.length > 0) {
            String contentType = request.getContentType();
            String charset = Optional.ofNullable(HttpUtil.getCharset(contentType)).orElse(StandardCharsets.UTF_8.name());
            String data = new String(bytes, Charset.forName(charset));
            EncryptorDataWrapper dataWrapper = WebContext.current().getDataConverter().load(request, data);
            byte[] decryptData = WebContext.current().getEncryptorFacade().decrypt(dataWrapper);
            request.setAttribute(CoreEncryptorConstant.KEY, dataWrapper.getKey());
            newInputstream = new BufferedInputStream(new ByteArrayInputStream(decryptData));
        } else {
            newInputstream = new ByteArrayInputStream(new byte[0]);
        }
        filterChain.doFilter(new HttpServletRequestWrapper(request) {

            @Override
            public ServletInputStream getInputStream() throws IOException {
                return new ServletInputStream() {
                    @Override
                    public int read() throws IOException {
                        return newInputstream.read();
                    }

                    @Override
                    public boolean isFinished() {
                        return true;
                    }

                    @Override
                    public boolean isReady() {
                        return true;
                    }

                    @Override
                    public void setReadListener(ReadListener listener) {
                    }
                };
            }

            @Override
            public BufferedReader getReader() throws IOException {
                return new BufferedReader(new InputStreamReader(getInputStream()));
            }
        }, response);
    }
}
