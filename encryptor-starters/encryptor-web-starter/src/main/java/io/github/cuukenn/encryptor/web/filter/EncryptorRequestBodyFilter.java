package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * 解密后的请求体视图（v2）：门面过滤器已一次性解密，这里只把 {@link WebContext#getBodyPlaintext()} 装进流包装器。
 *
 * @author changgg
 */
public class EncryptorRequestBodyFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        WebContext ctx = WebContext.current();
        if (!ctx.isReqEncryptor() || ctx.getBodyPlaintext() == null) {
            filterChain.doFilter(request, response);
            return;
        }
        byte[] plaintext = ctx.getBodyPlaintext();
        filterChain.doFilter(new HttpServletRequestWrapper(request) {
            @Override
            public ServletInputStream getInputStream() {
                ByteArrayInputStream in = new ByteArrayInputStream(plaintext);
                return new ServletInputStream() {
                    @Override
                    public int read() {
                        return in.read();
                    }

                    @Override
                    public boolean isFinished() {
                        return in.available() == 0;
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
            public BufferedReader getReader() {
                return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
            }

            // 明文长度才是下游（含 Jackson）应该看到的 body 长度；原密文长度是误导
            @Override
            public int getContentLength() {
                return plaintext.length;
            }

            @Override
            public long getContentLengthLong() {
                return plaintext.length;
            }

            @Override
            public String getContentType() {
                return request.getContentType();
            }
        }, response);
    }
}
