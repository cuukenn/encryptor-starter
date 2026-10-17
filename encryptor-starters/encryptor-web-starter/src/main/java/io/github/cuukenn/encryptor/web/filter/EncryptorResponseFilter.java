package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.UUID;

/**
 * 响应加密（v2）：只对"本请求确实协商出 CEK"的响应包装与加密；
 * 明文请求/透传请求完全不缓冲（修 v1 的无脑全量堆缓冲）。
 * black-res-content-type 判定放在链后（Content-Type 落定后，P1-9）。
 *
 * @author changgg
 */
public class EncryptorResponseFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorResponseFilter.class);
    private final EncryptorConfig protocol;
    private final DefaultProtocol protocolStack;

    public EncryptorResponseFilter(EncryptorConfig protocol, DefaultProtocol protocolStack) {
        this.protocol = protocol;
        this.protocolStack = protocolStack;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        WebContext ctx = WebContext.current();
        if (!ctx.isReqEncryptor() || ctx.getJweContext() == null) {
            filterChain.doFilter(request, response);
            return;
        }
        ContentCachingResponseWrapper wrapper = new ContentCachingResponseWrapper(response);
        filterChain.doFilter(request, wrapper);
        WebEncryptorConfig config = ctx.getConfig();
        String contentType = wrapper.getContentType();
        if (config != null && contentType != null
            && StrKit.anyMatch(contentType.toLowerCase(Locale.ROOT), config.getBlackResContentType())) {
            // 命中 black-res-content-type：原样放行；必须 copyBodyToResponse，否则客户端收到空响应
            wrapper.copyBodyToResponse();
            return;
        }
        byte[] body = wrapper.getContentAsByteArray();
        long maxResponseSize = protocol.getMaxResponseSize();
        if (maxResponseSize > 0 && body.length > maxResponseSize) {
            // 响应超限：不能发明文，也不把超大体留在缓存里
            logger.error("response too large to encrypt, uri: {}, size: {}", request.getRequestURI(), body.length);
            wrapper.resetBuffer();
            wrapper.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            wrapper.copyBodyToResponse();
            return;
        }
        try {
            long ts = System.currentTimeMillis();
            String nonce = UUID.randomUUID().toString();
            String compact = protocolStack.codec().encryptResponse(body, ctx.getJweContext().cek(),
                request.getRequestURI(), request.getMethod(), ts, nonce);
            wrapper.resetBuffer();
            wrapper.setContentType("application/json");
            wrapper.getOutputStream().write(("{\"jwe\":\"" + compact + "\"}").getBytes(StandardCharsets.UTF_8));
            wrapper.copyBodyToResponse();
        } catch (RuntimeException e) {
            // 业务已跑完、明文在缓存里：回 500 且丢弃明文，绝不把明文当密文发出去
            logger.error("response encrypt failed, uri: {}", request.getRequestURI(), e);
            wrapper.resetBuffer();
            wrapper.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            wrapper.copyBodyToResponse();
        }
    }
}
