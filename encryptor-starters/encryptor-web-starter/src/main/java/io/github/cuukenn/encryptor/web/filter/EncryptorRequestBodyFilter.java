package io.github.cuukenn.encryptor.web.filter;

import cn.hutool.core.io.IoUtil;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
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
        // 报文大小上限：这条路径在认证之前，且下面要把整个 body 读进内存，
        // 单个超大报文即可把堆打爆（见 open-issues.md P1-13）。超限一律回 413，不进下游链。
        int maxRequestSize = maxRequestSize();
        if (maxRequestSize > 0) {
            // 优先看 Content-Length：已知则直接判定，连读都不读
            if (request.getContentLengthLong() > maxRequestSize) {
                response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
                return;
            }
        }
        MediaType mediaType = MediaType.valueOf(Optional.ofNullable(request.getContentType()).orElseGet(MediaType.APPLICATION_JSON::toString));
        MessageReader messageReader = messageReaders.stream().filter(reader -> reader.canRead(mediaType))
                .findFirst()
                .orElseGet(DefaultMessageConverter::new);
        InputStream newInputstream;
        byte[] bytes;
        if (maxRequestSize > 0) {
            // 没有 Content-Length（chunked）时有界读取：最多读 limit+1 字节即可判定超限
            bytes = readBounded(request.getInputStream(), maxRequestSize);
            if (bytes == null) {
                response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
                return;
            }
        } else {
            bytes = IoUtil.readBytes(request.getInputStream());
        }
        if (bytes != null && bytes.length > 0) {
            byte[] decryptData;
            try {
                decryptData = messageReader.read().apply(request, response, bytes);
            } catch (EncryptorException e) {
                // 请求体解不开 = 报文非法：回 4xx，不进业务链
                response.setStatus(WebContext.failureStatus());
                return;
            }
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

    /**
     * 当前请求允许的最大 body 字节数；{@code <= 0} 表示不限制。
     *
     * <p>上下文还没被 {@code EncryptorWebFilter} 初始化时（过滤器被单独使用）按不限制处理。</p>
     */
    private static int maxRequestSize() {
        WebEncryptorConfig config = WebContext.current().getConfig();
        return config == null ? 0 : config.getMaxRequestSize();
    }

    /**
     * 有界读取：最多读 {@code limit + 1} 字节；一旦发现写满 {@code limit + 1} 字节即判定超限，返回 {@code null}。
     *
     * <p>用于没有 Content-Length 的 chunked 请求，避免 {@code IoUtil.readBytes} 那种"读到 EOF 为止"的无界行为。</p>
     */
    private static byte[] readBounded(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(limit, 8192));
        byte[] buffer = new byte[8192];
        int total = 0;
        while (total <= limit) {
            int read = in.read(buffer, 0, Math.min(buffer.length, limit + 1 - total));
            if (read == -1) {
                break;
            }
            total += read;
            if (total > limit) {
                return null;
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }
}
