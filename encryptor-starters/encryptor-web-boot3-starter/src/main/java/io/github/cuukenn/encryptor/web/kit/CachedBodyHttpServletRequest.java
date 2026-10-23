package io.github.cuukenn.encryptor.web.kit;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
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

            @Override
            public void setReadListener(ReadListener listener) {
                // 透传路径是同步读取，不需要非阻塞回调
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
