package io.github.cuukenn.encryptor.web.filter;

import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.JweCodec;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.CachedBodyHttpServletRequest;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import io.github.cuukenn.encryptor.web.kit.WebContext.Carrier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.util.StreamUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * 门面过滤器（v2）：统一识别 jwe 载体（query / JSON / form）、一次性解密并装载 {@link WebContext}；
 * 下游参数/请求体过滤器只消费结果，不再各自解密。决策（黑名单 / 运行期旁路 / require-encrypted）全部在此。
 *
 * @author changgg
 */
public class EncryptorWebFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorWebFilter.class);
    /** 声明长度预分配上限：超过它就走扩容路径，避免"大 Content-Length + 小 body"放大内存。 */
    private static final long READ_PREALLOC_LIMIT = 64 * 1024L;
    private final WebEncryptorConfig config;
    private final EncryptorConfig protocol;
    private final DefaultProtocol protocolStack;
    private final EncryptorRuntime runtime;

    public EncryptorWebFilter(WebEncryptorConfig config, EncryptorConfig protocol, DefaultProtocol protocolStack, EncryptorRuntime runtime) {
        this.config = config;
        this.protocol = protocol;
        this.protocolStack = protocolStack;
        this.runtime = runtime;
        logSkipSummary();
    }


    /** 启动期把四条名单与流式风险打到日志：默认名单/覆盖名单都能一眼看到。 */
    private void logSkipSummary() {
        logger.info("加密过滤名单: skip-uris={}, skip-methods={}, skip-req-content-type={}, skip-res-content-type={}",
            config.getSkipUris(), config.getSkipMethods(), config.getSkipReqContentType(), config.getSkipResContentType());
        boolean eventStream = false;
        for (String type : config.getSkipResContentType()) {
            if (type != null && type.toLowerCase(java.util.Locale.ROOT).contains("text/event-stream")) {
                eventStream = true;
                break;
            }
        }
        if (eventStream) {
            logger.warn("skip-res-content-type 含 text/event-stream：SSE 响应将不加密，直接明文输出");
        } else if (config.getSkipResContentType().isEmpty() && protocol.getMaxResponseSize() > 0) {
            logger.warn("skip-res-content-type 为空且 max-response-size={}：流式/大响应会被整体缓冲，超限返回失败",
                protocol.getMaxResponseSize());
        }
        if (protocol.getMaxRequestSize() <= 0) {
            logger.warn("encryptor.config.max-request-size<=0：请求体缓冲不设上限，JSON 载体会全量读入内存"
                + "（请配置 max-request-size 或 skip-req-content-type）");
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        WebContext ctx = WebContext.current();
        ctx.setConfig(config);
        ctx.setProtocol(protocol);
        // 入口重置（不能在链尾 clear：响应过滤器 order -10 包在本过滤器外层，
        // 链返回后还要读本上下文；最外层参数过滤器 -12 负责 finally clear）
        ctx.setReqEncryptor(false);
        ctx.setJweContext(null);
        ctx.setCarrier(WebContext.Carrier.NONE);
        ctx.setBodyPlaintext(null);
        ctx.setParameters(null);
        String uri = request.getRequestURI();
        // 名单与 uri 级 kid 白名单按"去掉 contextPath 的归一化路径"匹配（配置里写的是应用内路径）；
        // AAD 仍用原始 requestURI，与客户端 location.pathname 口径一致。
        String matchUri = ContextAad.canonicalPath(uri, request.getContextPath());
        String method = request.getMethod();
        // method 按规范大写归一后再匹配：配置写 get/Get/GET 都能命中
        if (StrKit.anyMatch(matchUri, config.getSkipUris()) || StrKit.anyMatch(method.toUpperCase(Locale.ROOT), config.getSkipMethods())) {
            filterChain.doFilter(request, response);
            return;
        }
        if (runtime.bypassRequest()) {
            filterChain.doFilter(request, response);
            return;
        }
        String contentType = request.getHeader(HttpHeaders.CONTENT_TYPE);
        String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (StrKit.anyMatch(ct, config.getSkipReqContentType())) {
            filterChain.doFilter(request, response);
            return;
        }
        String compact;
        Carrier carrier;
        byte[] cachedJsonBody = null;
        long maxRequestSize = WebContext.maxRequestSize();
        // 必须在 getParameter 之前判 Content-Length：表单载体一调用 getParameter，容器就会解析整个 body
        if (maxRequestSize > 0 && request.getContentLengthLong() > maxRequestSize) {
            fail(request, response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            return;
        }
        // chunked 表单没有 Content-Length，容器 getParameter 会无界解析整个 body；配置了上限时直接拒绝，
        // 与网关侧 readBody→413 的语义对齐（客户端应改用带 Content-Length 的请求）。
        if (maxRequestSize > 0 && ct.startsWith("application/x-www-form-urlencoded")
            && request.getContentLengthLong() < 0) {
            logger.warn("chunked 表单请求无法做有界校验，拒绝, uri: {}", uri);
            fail(request, response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            return;
        }
        compact = request.getParameter(EncryptorConstant.JWE_PARAM);
        if (compact != null && !compact.isEmpty()) {
            // getParameter 合并了 query 与 form body 两个来源：只有 jwe 确实来自 form body 时
            // 才按 FORM 处理（明文会同时替换参数与 body 视图）；jwe 在 query 上时必须按 QUERY
            // 处理（与网关侧同口径），否则明文会顶掉真实的 form body。
            carrier = !hasQueryJwe(request.getQueryString())
                && ct.startsWith("application/x-www-form-urlencoded") ? Carrier.FORM : Carrier.QUERY;
        } else if (isJson(ct)) {
            carrier = Carrier.JSON;
            byte[] raw = maxRequestSize > 0 ? readBounded(request.getInputStream(), maxRequestSize, request.getContentLengthLong()) : StreamUtils.copyToByteArray(request.getInputStream());
            if (raw == null) {
                fail(request, response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
                return;
            }
            cachedJsonBody = raw;
            if (raw.length == 0) {
                compact = null;
            } else {
                JSONObject envelope;
                try {
                    envelope = JSONUtil.parseObj(new String(raw, StandardCharsets.UTF_8));
                } catch (RuntimeException e) {
                    logger.warn("request body is not a valid json envelope, uri: {}", uri, e);
                    fail(request, response, WebContext.failureStatus());
                    return;
                }
                compact = envelope.getStr(EncryptorConstant.JWE_PARAM);
            }
        } else {
            carrier = Carrier.NONE;
        }
        if (compact == null || compact.isEmpty()) {
            if (WebContext.requireEncrypted()) {
                fail(request, response, WebContext.failureStatus());
                return;
            }
            // JSON 分支已经读过原始 body；透传时必须回放，否则下游看到的是空流
            HttpServletRequest passthrough = cachedJsonBody == null
                ? request : new CachedBodyHttpServletRequest(request, cachedJsonBody);
            filterChain.doFilter(passthrough, response);
            return;
        }
        JweContext jweCtx;
        try {
            jweCtx = protocolStack.openRequest(compact, uri, method);
        } catch (EncryptorException e) {
            logger.warn("decrypt request failed, uri: {}, failure: {}", uri, e.failure(), e);
            fail(request, response, WebContext.failureStatus());
            return;
        }
        // uri 级 kid 白名单（Ruling 8b-R4）：该 uri 只接受配置列出的 kid，空列表 = 不限
        List<String> accepted = acceptedKid(matchUri);
        if (accepted != null && !accepted.isEmpty() && !accepted.contains(jweCtx.kid())) {
            logger.warn("kid not accepted for uri: {}, kid: {}", uri, JweCodec.sanitize(jweCtx.kid()));
            jweCtx.destroy();
            fail(request, response, WebContext.failureStatus());
            return;
        }
        ctx.setJweContext(jweCtx);
        ctx.setCarrier(carrier);
        ctx.setReqEncryptor(true);
        if (carrier == Carrier.QUERY || carrier == Carrier.FORM) {
            try {
                ctx.setParameters(parseQuery(new String(jweCtx.plaintext(), StandardCharsets.UTF_8)));
            } catch (RuntimeException e) {
                logger.warn("decrypted parameters are not urlencoded text, uri: {}", uri, e);
                fail(request, response, WebContext.failureStatus());
                return;
            }
        }
        if (carrier == Carrier.JSON || carrier == Carrier.FORM) {
            ctx.setBodyPlaintext(jweCtx.plaintext());
        }
        filterChain.doFilter(request, response);
    }

    /**
     * 失败面统一出口：清上下文（提前 return 时最外层参数过滤器的 finally 不会执行，
     * 必须在这里清，否则 ThreadLocal/bodyPlaintext 会滞留到该线程的下一个请求）+ traceId 响应头 + 状态码。
     */
    private static void fail(HttpServletRequest request, HttpServletResponse response, int status) {
        String trace = UUID.randomUUID().toString();
        // 响应头与日志必须同值：客户端拿 trace 来排障时能在日志里 grep 到
        logger.warn("encrypt request failed, trace: {}, status: {}, {} {}", trace, status,
            request.getMethod(), request.getRequestURI());
        response.setHeader(EncryptorResponseFilter.TRACE_HEADER, trace);
        response.setStatus(status);
        WebContext.clear(request);
    }

    /** jwe 参数是否出现在 query string 上（name 支持百分号编码形态）。 */
    private static boolean hasQueryJwe(String queryString) {
        if (queryString == null || queryString.isEmpty()) {
            return false;
        }
        for (String pair : queryString.split("&")) {
            int index = pair.indexOf('=');
            String name = index < 0 ? pair : pair.substring(0, index);
            if (EncryptorConstant.JWE_PARAM.equals(name)) {
                return true;
            }
            try {
                if (EncryptorConstant.JWE_PARAM.equals(URLDecoder.decode(name, "UTF-8"))) {
                    return true;
                }
            } catch (IllegalArgumentException | UnsupportedEncodingException ignored) {
                // 非法编码交给后续解析路径处理
            }
        }
        return false;
    }

    /** JSON 载体：application/json 及其结构化后缀（application/vnd.api+json 等），忽略参数。 */
    private static boolean isJson(String contentType) {
        if (contentType == null) {
            return false;
        }
        try {
            MediaType type = MediaType.parseMediaType(contentType);
            return MediaType.APPLICATION_JSON.isCompatibleWith(type) || type.getSubtype().endsWith("+json");
        } catch (InvalidMediaTypeException e) {
            return false;
        }
    }

    private List<String> acceptedKid(String uri) {
        Map<String, List<String>> cryptoConfig = config.getCryptoConfig();
        if (cryptoConfig == null || cryptoConfig.isEmpty()) {
            return null;
        }
        String best = StrKit.getBestMatchStr(uri, cryptoConfig.keySet());
        return best == null ? null : cryptoConfig.get(best);
    }

    /**
     * 解析 urlencoded 明文为参数视图（保留多值；对 name/value 各做 UTF-8 URL 解码）。
     */
    private static Map<String, String[]> parseQuery(String text) {
        Map<String, List<String>> collected = new HashMap<>();
        for (String pair : text.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int index = pair.indexOf('=');
            String name = index < 0 ? pair : pair.substring(0, index);
            String value = index < 0 ? "" : pair.substring(index + 1);
            collected.computeIfAbsent(urlDecode(name), k -> new ArrayList<>())
                .add(urlDecode(value));
        }
        Map<String, String[]> parameters = new HashMap<>();
        collected.forEach((name, values) -> parameters.put(name, values.toArray(new String[0])));
        // Servlet 规范：getParameterMap 不得被应用修改——下游 put 会污染本请求共享视图
        return java.util.Collections.unmodifiableMap(parameters);
    }

    private static String urlDecode(String text) {
        try {
            return URLDecoder.decode(text, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 必然存在", e);
        }
    }

    /**
     * 有界读取：最多读 {@code limit + 1} 字节；写满即判定超限返回 {@code null}（chunked 无 Content-Length 时防堆打爆）。
     *
     * <p>声明长度只用于"小包快路径"预分配：客户端可在只发几个字节的情况下声明任意 Content-Length，
     * 按声明值全额分配会变成内存放大 DoS；超过 {@link #READ_PREALLOC_LIMIT} 一律走扩容路径。</p>
     */
    private static byte[] readBounded(InputStream in, long limit, long contentLength) throws IOException {
        if (contentLength > 0 && contentLength <= limit && contentLength <= READ_PREALLOC_LIMIT) {
            // 声明长度可信时一次分配到位，省掉 8KB 起步的反复扩容与最终 toByteArray 复制
            byte[] body = new byte[(int) contentLength];
            int offset = 0;
            while (offset < body.length) {
                int read = in.read(body, offset, body.length - offset);
                if (read == -1) {
                    return Arrays.copyOf(body, offset);
                }
                offset += read;
            }
            // 声明长度小于实际 body：多读一字节判定超限，不能让"少报 Content-Length"绕过上限
            return in.read() == -1 ? body : null;
        }
        long initial = contentLength > 0 ? Math.min(contentLength, READ_PREALLOC_LIMIT) : 8192;
        return readBounded(in, limit, (int) Math.min(initial, Math.min(limit, Integer.MAX_VALUE)));
    }

    private static byte[] readBounded(InputStream in, long limit) throws IOException {
        return readBounded(in, limit, (int) Math.min(limit, 8192));
    }

    private static byte[] readBounded(InputStream in, long limit, int initialCapacity) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(initialCapacity);
        byte[] buffer = new byte[8192];
        long total = 0;
        while (total <= limit) {
            int read = in.read(buffer, 0, (int) Math.min(buffer.length, limit + 1 - total));
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
