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

import javax.servlet.AsyncContext;
import javax.servlet.AsyncEvent;
import javax.servlet.AsyncListener;
import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

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
        AsyncTrackingRequest trackingRequest = new AsyncTrackingRequest(request, wrapper, ctx);
        try {
            filterChain.doFilter(trackingRequest, wrapper);
        } catch (Exception e) {
            // 业务异常不能交给容器错误页：那会把明文写到已包装响应之外。
            logger.error("encryptor response filter caught exception, uri: {}", request.getRequestURI(), e);
            if (trackingRequest.isAsyncStarted()) {
                // 异步已启动：初始线程不能再 reset/commit 响应（与监听器生命周期脱节，
                // 客户端只会得到空 500）。CEK/明文的收尾交给 AsyncListener（onError/onComplete/
                // onTimeout 必然触发其一）；异步在上游开启、还没挂监听器的这里补挂。
                if (!trackingRequest.isTrackedAsync()) {
                    deferAsync(trackingRequest, wrapper, ctx);
                }
                return;
            }
            fail(wrapper, request.getRequestURI(), "unhandled exception: " + e);
            return;
        }
        // 异步请求由 AsyncListener 在 onComplete 时再加密；此时不能提前读空缓存，
        // 也不能让参数过滤器的 finally 提前清掉 JweContext（CEK）。
        if (trackingRequest.isAsyncStarted()) {
            if (!trackingRequest.isTrackedAsync()) {
                // 上游过滤器已经开启异步时，startAsync 不会经过本包装器，补挂一次监听器。
                deferAsync(trackingRequest, wrapper, ctx);
            }
            return;
        }
        try {
            finish(trackingRequest, wrapper, ctx.getJweContext(), ctx.getConfig());
        } catch (Exception e) {
            logger.error("encryptor response filter finish failed, uri: {}", request.getRequestURI(), e);
            fail(wrapper, request.getRequestURI(), "response finish failed: " + e);
        }
    }

    /**
     * 同步/异步共用的收尾：刷新缓存 → 提交约束检查 → 加密或原样复制。
     *
     * <p>异步路径不能读 {@link WebContext}（回调线程与请求线程不同），因此 JweContext 与
     * WebEncryptorConfig 由调用方显式传入。</p>
     */
    private void finish(HttpServletRequest request, BoundedContentCachingResponseWrapper wrapper,
                        JweContext jweContext, WebEncryptorConfig config) throws IOException {
        wrapper.flushBuffer();
        // 业务/容器已直接提交（例如流式写入、绕过 wrapper 的 sendError）：不能再改写，
        // 否则会向已提交响应追加 JWE，真实容器里直接 IllegalStateException。
        if (wrapper.isCommitted()) {
            // 明文可能已经出网：至少要留审计痕迹，不能静默
            logger.warn("response already committed before encryptor finish, plaintext may have leaked "
                + "unencrypted (business bypassed the wrapper?), uri: {}", request.getRequestURI());
            return;
        }
        // HEAD 与规范禁止 body 的状态（1xx/204/205/304）不加密。
        if (isHead(request) || isNoBodyStatus(wrapper.getStatus())) {
            wrapper.resetBuffer();
            return;
        }
        String uri = request.getRequestURI();
        if (wrapper.isOverflow()) {
            fail(wrapper, uri, "response exceeds max-response-size(" + protocol.getMaxResponseSize() + ")");
            return;
        }
        // 重定向只在确实没有 body 时跳过；带 body 的 3xx 仍按普通响应加密
        // （HTTP 允许 3xx 携带说明性 body）。溢出优先，不能把超限 body 当成空 body 静默放行。
        if (isRedirect(wrapper.getStatus()) && wrapper.getContentSize() == 0) {
            wrapper.resetBuffer();
            return;
        }
        // media-type 段（剥 ;charset= 等参数）匹配：SSE 等常带参数的真实头也要能命中名单
        String contentType = StrKit.mediaType(wrapper.getContentType());
        if (config != null && contentType != null
            && StrKit.anyMatch(contentType.toLowerCase(Locale.ROOT), config.getSkipResContentType())) {
            wrapper.copyBodyToResponse();
            return;
        }
        byte[] body = wrapper.getContentAsByteArray();
        try {
            String compact = protocolStack.codec().encryptResponse(body, jweContext.cek(),
                jweContext.enc(), uri, request.getMethod(), System.currentTimeMillis(),
                UUID.randomUUID().toString());
            wrapper.resetBuffer();
            wrapper.setContentType("application/json");
            clearContentEncoding(wrapper);
            wrapper.writeEncryptedEnvelope(compact);
            wrapper.copyBodyToResponse();
        } catch (RuntimeException e) {
            fail(wrapper, uri, "response encrypt failed: " + e);
        }
    }

    /**
     * 把响应生命周期交给异步回调：先把 CEK 从 ThreadLocal 上下文摘下，避免参数过滤器 finally
     * 在异步完成前 destroy；随后在 onComplete/onError/onTimeout 中收尾并销毁。
     *
     * <p><b>契约</b>：异步周期必须可终止（设置 {@code setTimeout} 或保证 {@code complete()}）。
     * {@code setTimeout(0)} 且永不 complete 时，CEK 与响应明文缓存会滞留到 GC——这是
     * Servlet 异步模型的固有限制，本过滤器不做 per-request 的 requestDestroyed 兜底。</p>
     */
    private void deferAsync(HttpServletRequest request, BoundedContentCachingResponseWrapper wrapper, WebContext ctx) {
        JweContext jweContext = ctx.getJweContext();
        WebEncryptorConfig config = ctx.getConfig();
        // 所有权移交给监听器：参数过滤器的 finally 不能再 destroy CEK，也不能提前清零
        // 异步处理器仍可能读取的请求明文；两者都由监听器在异步结束时销毁。
        ctx.setJweContext(null);
        ctx.setBodyPlaintext(null);
        try {
            request.getAsyncContext().addListener(new AsyncResponseListener(request, wrapper, jweContext, config));
        } catch (RuntimeException e) {
            logger.error("encryptor async response listener registration failed, uri: {}", request.getRequestURI(), e);
            try {
                fail(wrapper, request.getRequestURI(), "async listener registration failed: " + e);
            } catch (IOException ioException) {
                logger.error("encryptor async response failure write failed, uri: {}", request.getRequestURI(), ioException);
            }
            jweContext.destroy();
        }
    }

    /**
     * 拦截业务发起的 {@code startAsync()}，在异步周期创建的第一时间挂监听器，
     * 避免“业务很快 complete，而过滤器链返回后才 addListener”导致 onComplete 丢事件。
     */
    private final class AsyncTrackingRequest extends HttpServletRequestWrapper {
        private final BoundedContentCachingResponseWrapper wrapper;
        private final WebContext ctx;
        private final AtomicBoolean tracked = new AtomicBoolean(false);

        private AsyncTrackingRequest(HttpServletRequest request, BoundedContentCachingResponseWrapper wrapper, WebContext ctx) {
            super(request);
            this.wrapper = wrapper;
            this.ctx = ctx;
        }

        @Override
        public AsyncContext startAsync() {
            return track(super.startAsync());
        }

        @Override
        public AsyncContext startAsync(ServletRequest request, ServletResponse response) {
            return track(super.startAsync(request, response));
        }

        private boolean isTrackedAsync() {
            return tracked.get();
        }

        private AsyncContext track(AsyncContext async) {
            if (!tracked.compareAndSet(false, true)) {
                return async;
            }
            JweContext jweContext = ctx.getJweContext();
            WebEncryptorConfig config = ctx.getConfig();
            // 所有权移交给监听器：参数过滤器的 finally 不能再 destroy 这把 CEK；
            // 请求明文也可能被异步处理器继续读取，必须等异步结束再由监听器清零。
            ctx.setJweContext(null);
            ctx.setBodyPlaintext(null);
            AsyncResponseListener listener = new AsyncResponseListener(this, wrapper, jweContext, config);
            try {
                async.addListener(listener);
            } catch (RuntimeException e) {
                jweContext.destroy();
                throw e;
            }
            return new TrackingAsyncContext(async, listener);
        }
    }

    /**
     * 在业务调用 {@link AsyncContext#complete()} 时先收尾，再交给容器 complete。
     *
     * <p>Servlet 规范只保证 {@code onComplete} 是通知，并不保证此时还能安全写响应；
     * 因此主路径在 complete 之前加密，{@code onComplete} 保留为兜底（同一个 done 标志防重）。</p>
     */
    private static final class TrackingAsyncContext implements AsyncContext {
        private final AsyncContext delegate;
        private final AsyncResponseListener listener;

        private TrackingAsyncContext(AsyncContext delegate, AsyncResponseListener listener) {
            this.delegate = delegate;
            this.listener = listener;
        }

        @Override
        public ServletRequest getRequest() {
            return delegate.getRequest();
        }

        @Override
        public ServletResponse getResponse() {
            return delegate.getResponse();
        }

        @Override
        public boolean hasOriginalRequestAndResponse() {
            return delegate.hasOriginalRequestAndResponse();
        }

        @Override
        public void dispatch() {
            delegate.dispatch();
        }

        @Override
        public void dispatch(String path) {
            delegate.dispatch(path);
        }

        @Override
        public void dispatch(ServletContext context, String path) {
            delegate.dispatch(context, path);
        }

        @Override
        public void complete() {
            listener.finishNow();
            delegate.complete();
        }

        @Override
        public void start(Runnable run) {
            delegate.start(run);
        }

        @Override
        public void addListener(AsyncListener listener) {
            delegate.addListener(listener);
        }

        @Override
        public void addListener(AsyncListener listener, ServletRequest request, ServletResponse response) {
            delegate.addListener(listener, request, response);
        }

        @Override
        public <T extends AsyncListener> T createListener(Class<T> clazz) throws ServletException {
            return delegate.createListener(clazz);
        }

        @Override
        public void setTimeout(long timeout) {
            delegate.setTimeout(timeout);
        }

        @Override
        public long getTimeout() {
            return delegate.getTimeout();
        }
    }

    /** 异步完成时加密响应；失败/超时回空 500，保证不把缓存中的明文交给客户端。 */
    private final class AsyncResponseListener implements AsyncListener {
        private final HttpServletRequest request;
        private final BoundedContentCachingResponseWrapper wrapper;
        private final JweContext jweContext;
        private final WebEncryptorConfig config;
        private final AtomicBoolean done = new AtomicBoolean(false);

        private AsyncResponseListener(HttpServletRequest request, BoundedContentCachingResponseWrapper wrapper,
                                      JweContext jweContext, WebEncryptorConfig config) {
            this.request = request;
            this.wrapper = wrapper;
            this.jweContext = jweContext;
            this.config = config;
        }

        @Override
        public void onComplete(AsyncEvent event) {
            finishNow();
        }

        /**
         * 主路径（拦截 complete）与 onComplete 兜底共用；done 保证只执行一次。
         */
        private void finishNow() {
            if (!done.compareAndSet(false, true)) {
                return;
            }
            try {
                finish(request, wrapper, jweContext, config);
            } catch (Exception e) {
                logger.error("encryptor async response finish failed, uri: {}", request.getRequestURI(), e);
                safeFail("async finish failed: " + e);
            } finally {
                jweContext.destroy();
            }
        }

        @Override
        public void onTimeout(AsyncEvent event) {
            if (!done.compareAndSet(false, true)) {
                return;
            }
            try {
                safeFail("async timeout");
            } finally {
                jweContext.destroy();
            }
        }

        @Override
        public void onError(AsyncEvent event) {
            if (!done.compareAndSet(false, true)) {
                return;
            }
            logger.error("encryptor async request failed, uri: {}", request.getRequestURI(), event.getThrowable());
            try {
                safeFail("async error");
            } finally {
                jweContext.destroy();
            }
        }

        @Override
        public void onStartAsync(AsyncEvent event) {
            // 异步周期重新开始时，新上下文需要重新挂监听器。
            if (!done.get()) {
                try {
                    event.getAsyncContext().addListener(this);
                } catch (RuntimeException e) {
                    logger.warn("encryptor async listener re-registration failed, uri: {}",
                        request.getRequestURI(), e);
                }
            }
        }

        private void safeFail(String reason) {
            if (wrapper.isCommitted()) {
                return;
            }
            try {
                fail(wrapper, request.getRequestURI(), reason);
            } catch (IOException e) {
                logger.error("encryptor async response failure write failed, uri: {}", request.getRequestURI(), e);
            }
        }
    }


    private static boolean isHead(HttpServletRequest request) {
        return "HEAD".equalsIgnoreCase(request.getMethod());
    }

    /** HTTP 规范上不允许带 body 的响应：1xx、204/205/304。 */
    private static boolean isNoBodyStatus(int status) {
        return (status >= 100 && status < 200)
            || status == 204 || status == 205 || status == 304;
    }

    /** 3xx 重定向：允许携带说明性 body，仅在 body 为空时跳过加密。 */
    private static boolean isRedirect(int status) {
        return status >= 300 && status < 400;
    }

    private void fail(BoundedContentCachingResponseWrapper wrapper, String uri, String reason) throws IOException {
        String trace = UUID.randomUUID().toString();
        logger.error("encryptor response failure, trace: {}, uri: {}, reason: {}", trace, uri, reason);
        // 响应已提交时不能再 reset/改状态，否则会从失败处理里再抛 IllegalStateException
        if (wrapper.isCommitted()) {
            return;
        }
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
