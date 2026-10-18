package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.UUID;

/**
 * 响应加密（v2）：只对"本请求确实协商出 CEK 且响应方向未旁路"的响应包装与加密。
 *
 * <p>缓冲有界（C3b）：超过 {@code max-response-size} 即停止缓冲并回 500（不发明文）；
 * 大文件/流式接口应把其 content-type 加入 {@code skip-res-content-type}，
 * 并把 {@code max-response-size} 设为 {@code <= 0} 以关闭该上限。</p>
 *
 * <p>运行期止血：{@code EncryptorRuntime.bypassResponse()} 为 true 时原样透传（与网关一致）。</p>
 *
 * @author changgg
 */
public class EncryptorResponseFilter extends OncePerRequestFilter {
    /** 失败响应的排障标识（与日志里的同一值对应）。 */
    public static final String TRACE_HEADER = EncryptorConstant.TRACE_HEADER;
    private static final Logger logger = LoggerFactory.getLogger(EncryptorResponseFilter.class);
    private final EncryptorConfig protocol;
    private final DefaultProtocol protocolStack;
    private final EncryptorRuntime runtime;

    public EncryptorResponseFilter(EncryptorConfig protocol, DefaultProtocol protocolStack) {
        this(protocol, protocolStack, protocolStack.runtime());
    }

    public EncryptorResponseFilter(EncryptorConfig protocol, DefaultProtocol protocolStack, EncryptorRuntime runtime) {
        this.protocol = protocol;
        this.protocolStack = protocolStack;
        this.runtime = runtime;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        WebContext ctx = WebContext.current();
        if (!ctx.isReqEncryptor() || ctx.getJweContext() == null || runtime.bypassResponse()) {
            filterChain.doFilter(request, response);
            return;
        }
        long maxResponseSize = protocol.getMaxResponseSize();
        BoundedContentCachingResponseWrapper wrapper = new BoundedContentCachingResponseWrapper(response,
            maxResponseSize > 0 ? maxResponseSize : Long.MAX_VALUE);
        filterChain.doFilter(request, wrapper);
        wrapper.flushBuffer();
        String uri = request.getRequestURI();
        if (wrapper.isOverflow()) {
            fail(wrapper, uri, "response exceeds max-response-size(" + maxResponseSize + ")");
            return;
        }
        WebEncryptorConfig config = ctx.getConfig();
        String contentType = wrapper.getContentType();
        if (config != null && contentType != null
            && StrKit.anyMatch(contentType.toLowerCase(Locale.ROOT), config.getSkipResContentType())) {
            wrapper.copyBodyToResponse();
            return;
        }
        byte[] body = wrapper.getContentAsByteArray();
        try {
            String compact = protocolStack.codec().encryptResponse(body, ctx.getJweContext().cek(),
                ctx.getJweContext().enc(), uri, request.getMethod(), System.currentTimeMillis(),
                UUID.randomUUID().toString());
            wrapper.resetBuffer();
            wrapper.setContentType("application/json");
            clearContentEncoding(wrapper);
            wrapper.getOutputStream().write(("{\"jwe\":\"" + compact + "\"}").getBytes(StandardCharsets.UTF_8));
            wrapper.copyBodyToResponse();
        } catch (RuntimeException e) {
            fail(wrapper, uri, "response encrypt failed: " + e);
        }
    }

    private void fail(BoundedContentCachingResponseWrapper wrapper, String uri, String reason) throws IOException {
        String trace = UUID.randomUUID().toString();
        logger.error("encryptor response failure, trace: {}, uri: {}, reason: {}", trace, uri, reason);
        wrapper.resetBuffer();
        wrapper.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        wrapper.setHeader(TRACE_HEADER, trace);
        clearContentEncoding(wrapper);
        wrapper.copyBodyToResponse();
    }

    /**
     * body 已被替换（JWE JSON 或空的 500），下游若声明过 {@code Content-Encoding}（如 gzip）必须改写为
     * {@code identity}，否则客户端会按 gzip 解压 JWE JSON 得到乱码。Servlet API 没有"删头"语义
     * （{@code setHeader(name, null)} 在 Spring 的 mock 里直接抛异常），故用 identity 覆盖。
     */
    private static void clearContentEncoding(HttpServletResponse response) {
        String encoding = response.getHeader("Content-Encoding");
        if (encoding != null && !encoding.isEmpty()) {
            response.setHeader("Content-Encoding", "identity");
        }
    }
}
