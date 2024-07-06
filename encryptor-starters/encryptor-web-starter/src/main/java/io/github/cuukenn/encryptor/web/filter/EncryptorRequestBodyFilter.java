package io.github.cuukenn.encryptor.web.filter;

import cn.hutool.core.io.IoUtil;
import io.github.cuukenn.encryptor.web.converter.DefaultMessageConverter;
import io.github.cuukenn.encryptor.web.converter.MessageReader;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.List;
import java.util.Optional;

/**
 * 解密request body
 *
 * @author changgg
 */
public class EncryptorRequestBodyFilter extends OncePerRequestFilter {
    private final List<MessageReader> messageReaders;

    public EncryptorRequestBodyFilter(List<MessageReader> messageReaders) {
        this.messageReaders = messageReaders;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!WebContext.current().isReqEncryptor()) {
            filterChain.doFilter(request, response);
            return;
        }
        MediaType mediaType = MediaType.valueOf(Optional.ofNullable(request.getContentType()).orElseGet(MediaType.APPLICATION_JSON::toString));
        MessageReader messageReader = messageReaders.stream().filter(reader -> reader.canRead(mediaType))
                .findFirst()
                .orElseGet(DefaultMessageConverter::new);
        InputStream newInputstream;
        byte[] bytes = IoUtil.readBytes(request.getInputStream());
        if (bytes != null && bytes.length > 0) {
            byte[] decryptData = messageReader.read().apply(request, response, bytes);
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
