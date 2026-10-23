package io.github.cuukenn.encryptor.web.filter;

import org.springframework.web.util.ContentCachingResponseWrapper;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
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
    private static final byte[] ENVELOPE_PREFIX = "{\"jwe\":\"".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] ENVELOPE_SUFFIX = "\"}".getBytes(StandardCharsets.US_ASCII);

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

    /**
     * 父类的 {@code setContentLength} 会 {@code content.resize(len)} 预分配。
     * 声明长度超过上限时必须在分配之前拦截：置溢出交给外层回 500，
     * 而不是先吃掉 100MB 堆再发现超限。
     */
    @Override
    public void setContentLength(int len) {
        if (acceptDeclaredLength(len)) {
            super.setContentLength(len);
        }
    }

    @Override
    public void setContentLengthLong(long len) {
        if (acceptDeclaredLength(len)) {
            super.setContentLengthLong(len);
        }
    }

    @Override
    public void setBufferSize(int size) {
        if (size < 0) {
            return;
        }
        // buffer size 只是提示，不代表响应体一定超限：收敛到上限即可，不能据此判定溢出
        super.setBufferSize((int) Math.min(size, limit));
    }

    /**
     * 声明长度的准入判断：负值忽略；超过上限置溢出；未配置上限时忽略父类无法表示（>2GB）的声明，
     * 交给实际写入决定，避免把 {@link IllegalArgumentException} 抛进业务代码。
     */
    private boolean acceptDeclaredLength(long len) {
        if (len < 0) {
            return false;
        }
        if (len > limit) {
            overflow = true;
            return false;
        }
        return len <= Integer.MAX_VALUE;
    }

    /** {@code reset()} 会清空缓存、头与状态，计数/溢出标记也必须一起复位。 */
    @Override
    public void reset() {
        if (writer != null) {
            writer.flush();
        }
        super.reset();
        overflow = false;
        if (stream != null) {
            stream.written = 0L;
        }
    }

    /**
     * 清空缓存时同步复位计数与溢出标记：缓存大小与 {@code written} 必须保持一致。
     * 否则清掉明文后写入的 JWE 仍会带着旧明文的字节数参与上限判断，
     * 接近上限的正常响应会被误判为溢出（空 200），{@code sendError} 也会退化成 500。
     */
    @Override
    public void resetBuffer() {
        if (writer != null) {
            writer.flush();
        }
        super.resetBuffer();
        overflow = false;
        if (stream != null) {
            stream.written = 0L;
        }
    }

    /**
     * 写入加密后的响应体：上限约束的是业务明文，JWE 的 Base64 膨胀不应再被同一個上限截断。
     * 直接走父类的缓存流，绕过 {@link BoundedServletOutputStream} 的计数。
     */
    /**
     * 分三段写响应信封，避免把 base64 密文先拼成一份 UTF-16 {@code String} 再转字节：
     * 大响应下这一步会额外产生约 2× 密文大小的字符数组。
     */
    void writeEncryptedEnvelope(String compact) throws IOException {
        ServletOutputStream out = super.getOutputStream();
        out.write(ENVELOPE_PREFIX);
        out.write(compact.getBytes(StandardCharsets.US_ASCII));
        out.write(ENVELOPE_SUFFIX);
    }

    /**
     * 拦截 {@code sendError}：Spring 的默认实现会先把缓存 body 复制到真实响应并提交，
     * 之后外层再也无法把错误响应换成 JWE（真实容器里会变成明文错误页）。
     * 这里只改状态/缓存内容，由外层响应过滤器统一加密。
     */
    @Override
    public void sendError(int sc) throws IOException {
        sendError(sc, null);
    }

    @Override
    public void sendError(int sc, String msg) throws IOException {
        requireNotCommitted("sendError");
        discardBufferedBody();
        setStatus(sc);
        if (msg != null) {
            setContentType("text/plain;charset=UTF-8");
            // 不能复用 getWriter()：它可能已被业务按其他字符集创建，setContentType 不会改变已有 writer 的编码。
            getOutputStream().write(msg.getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * 同理拦截 {@code sendRedirect}：默认实现会复制已写入的 body 并提交响应。
     * 重定向不承载业务 body，清空缓存后只保留状态与 Location，由容器在过滤器链结束后提交。
     */
    @Override
    public void sendRedirect(String location) throws IOException {
        requireNotCommitted("sendRedirect");
        discardBufferedBody();
        setStatus(HttpServletResponse.SC_FOUND);
        setHeader("Location", encodeRedirectURL(location));
    }

    /** Servlet 契约：响应已提交后不能再 sendError/sendRedirect。 */
    private void requireNotCommitted(String action) {
        if (isCommitted()) {
            throw new IllegalStateException("响应已提交，无法 " + action);
        }
    }

    /** 先把 PrintWriter 里的字符落盘，再清缓存；否则旧内容会在下一次 flush 时混进新 body。 */
    private void discardBufferedBody() {
        if (writer != null) {
            writer.flush();
        }
        resetBuffer();
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
