package io.github.cuukenn.encryptor.web.kit;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * 已缓存请求体的包装器：门面过滤器为了识别 JSON 载体读过流后，透传场景仍能把原始 body 交给下游。
 *
 * <p>只覆盖 body 读取视图（输入流/Reader/Content-Length），参数、请求头等仍委托原请求。</p>
 *
 * @author changgg
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {
    private final byte[] body;

    public CachedBodyHttpServletRequest(HttpServletRequest request, byte[] body) {
        super(request);
        this.body = body == null ? new byte[0] : body;
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream in = new ByteArrayInputStream(body);
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

            // 明文是内存字节数组、同步可读；静默吞掉监听器会让下游非阻塞读永远挂起——显式拒绝
            @Override
            public void setReadListener(ReadListener listener) {
                throw new UnsupportedOperationException(
                    "非阻塞读不支持缓存请求体视图（明文已在内存中，请使用同步读取）");
            }
        };
    }

    @Override
    public String getCharacterEncoding() {
        return "UTF-8";
    }

    @Override
    public String getContentType() {
        String contentType = super.getContentType();
        // 透传 body 是按 UTF-8 重放字节的：去掉原 charset，避免下游按其它编码解码
        return contentType == null ? null : contentType.replaceAll("(?i);\\s*charset=[^;]*", "");
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }

    @Override
    public int getContentLength() {
        return body.length;
    }

    @Override
    public long getContentLengthLong() {
        return body.length;
    }
}
