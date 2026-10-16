package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.web.converter.DefaultMessageConverter;
import io.github.cuukenn.encryptor.web.converter.MessageWriter;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * @author changgg
 */
public class EncryptorResponseFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorResponseFilter.class);
    private final List<MessageWriter> messageWriters;

    public EncryptorResponseFilter(List<MessageWriter> messageWriters) {
        this.messageWriters = messageWriters;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 响应类型黑名单只能等 handler 跑完、Content-Type 落定之后才能判定：
        // 过滤器入口处响应还没有 Content-Type，在那里判定等于永远不生效（见 open-issues.md P1-9）。
        // 所以这里只按"请求方向是否需要加密"决定是否包装，黑名单判定挪到链后。
        if (!WebContext.current().isReqEncryptor()) {
            filterChain.doFilter(request, response);
            return;
        }
        ContentCachingResponseWrapper cachingResponseWrapper = new ContentCachingResponseWrapper(response);
        filterChain.doFilter(request, cachingResponseWrapper);
        // 没有协商出 key（例如没有加密参数的明文 GET）：响应无从加密。
        // 以前会带着 key=null 去走 RSA，客户端拿到 500；现在按"本次请求没协商加密"原样放行。
        String key = (String) request.getAttribute(CoreEncryptorConstant.KEY);
        if (key == null || !WebContext.isResEncryptorEnable(response)) {
            // 命中 black-res-content-type：原样放行。
            // 必须 copyBodyToResponse，否则响应体还留在缓存 wrapper 里，客户端会收到空响应。
            cachingResponseWrapper.copyBodyToResponse();
            return;
        }
        MessageWriter messageWriter = messageWriters.stream().filter(writer -> writer.canWrite(MediaType.valueOf(Optional.ofNullable(response.getContentType()).orElseGet(MediaType.APPLICATION_JSON::toString))))
                .findFirst()
                .orElseGet(DefaultMessageConverter::new);
        byte[] encryptedData;
        try {
            encryptedData = messageWriter.write().apply(request, response, cachingResponseWrapper.getContentAsByteArray());
        } catch (EncryptorException e) {
            // 业务已经跑完、响应体在缓存里，这里无法再把业务结果拿回来 —— 这是服务端/协商问题，回 500。
            // 注意要丢掉缓存体：否则会把明文原样当成"加密结果"发出去。
            logger.error("response encrypt failed, uri: {}", request.getRequestURI(), e);
            cachingResponseWrapper.resetBuffer();
            cachingResponseWrapper.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            cachingResponseWrapper.copyBodyToResponse();
            return;
        }
        cachingResponseWrapper.resetBuffer();
        cachingResponseWrapper.getOutputStream().write(encryptedData);
        cachingResponseWrapper.copyBodyToResponse();
    }
}
