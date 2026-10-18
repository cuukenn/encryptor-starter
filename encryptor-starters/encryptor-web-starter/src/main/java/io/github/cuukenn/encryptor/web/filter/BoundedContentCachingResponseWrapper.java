package io.github.cuukenn.encryptor.web.filter;

import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * 有界响应缓冲（C3b）：累计写入超过 {@code limit} 的字节不再进缓冲，只置溢出标记。
 *
 * <p>Spring 的 {@link ContentCachingResponseWrapper} 把字节缓存在内部流里，没有"写入挂钩"，
 * 所以这里覆写 {@link #getOutputStream()}/{@link #getWriter()} 进行计数。溢出的响应体不完整，
 * 调用方必须放弃包装（回 500），不能把半截内容当明文透传。</p>
 *
 * @author changgg
 */
class BoundedContentCachingResponseWrapper extends ContentCachingResponseWrapper {
    private final long limit;
    private boolean overflow;
    private BoundedServletOutputStream stream;
    private PrintWriter writer;

    BoundedContentCachingResponseWrapper(HttpServletResponse response, long limit) {
        super(response);
        this.limit = limit;
    }

    /** 是否已因超限丢弃过字节（此时缓存内容不完整）。 */
    boolean isOverflow() {
        return overflow;
    }

    /** 已尝试写入的总字节数（溢出时是"至少这么多"）。 */
    long writtenSize() {
        return stream == null ? 0L : stream.written;
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        if (stream == null) {
            stream = new BoundedServletOutputStream(super.getOutputStream());
        }
        return stream;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (writer == null) {
            String encoding = getCharacterEncoding();
            Charset charset = encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding);
            writer = new PrintWriter(new OutputStreamWriter(getOutputStream(), charset), true);
        }
        return writer;
    }

    @Override
    public void flushBuffer() throws IOException {
        // 业务经 getWriter() 写出的内容停在 PrintWriter 缓冲里，必须先落到内部缓存流
        if (writer != null) {
            writer.flush();
        }
        super.flushBuffer();
    }

    private final class BoundedServletOutputStream extends ServletOutputStream {
        private final ServletOutputStream delegate;
        private long written;

        private BoundedServletOutputStream(ServletOutputStream delegate) {
            this.delegate = delegate;
        }

        @Override
        public void write(int b) throws IOException {
            if (accept(1)) {
                delegate.write(b);
                written++;
            }
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (accept(len)) {
                delegate.write(b, off, len);
                written += len;
            }
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setWriteListener(WriteListener writeListener) {
            delegate.setWriteListener(writeListener);
        }

        private boolean accept(int length) {
            if (overflow) {
                return false;
            }
            if (written + (long) length > limit) {
                overflow = true;
                return false;
            }
            return true;
        }
    }
}
