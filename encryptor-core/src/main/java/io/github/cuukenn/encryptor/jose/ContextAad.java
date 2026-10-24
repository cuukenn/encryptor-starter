package io.github.cuukenn.encryptor.jose;

import io.github.cuukenn.encryptor.exception.EncryptorException;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 上下文绑定（AAD）。
 *
 * <p>JWE Compact 序列化没有独立的 AAD 字段：按 RFC 7516，AAD 就是
 * {@code ASCII(BASE64URL(protected header))}。因此"绑定上下文"的实现方式是把下面这些 claim
 * 放进 <b>protected header</b>——它们随 tag 一起被认证，篡改必然被发现。
 *
 * <p>绑定的上下文：{@code uri}、{@code m}（method）、{@code dir}（方向）、{@code ts}、{@code nonce}。
 *
 * @author changgg
 */
public final class ContextAad {

    public static final String CLAIM_URI = "uri";
    public static final String CLAIM_METHOD = "m";
    public static final String CLAIM_DIRECTION = "dir";
    public static final String CLAIM_TS = "ts";
    public static final String CLAIM_NONCE = "nonce";

    private ContextAad() {
    }

    /**
     * 规范化路径：去掉 contextPath、去掉 query、百分号解码、折叠 {@code .}/{@code ..} 段。
     *
     * <p>两端必须得到同一个字符串：servlet 传 {@code request.getRequestURI()} 与 contextPath（原始、未解码），
     * 网关传 {@code exchange.getRequest().getURI().getPath()}（已解码）与空 contextPath。
     *
     * @param requestUri 原始请求 uri（可含 query）
     * @param contextPath 应用上下文路径，可为 null/空/{@code "/"}
     */
    public static String canonicalPath(String requestUri, String contextPath) {
        String path = requestUri == null ? "/" : requestUri;
        if (contextPath != null && !contextPath.isEmpty() && !"/".equals(contextPath) && path.startsWith(contextPath)) {
            path = path.substring(contextPath.length());
        }
        int queryIndex = path.indexOf('?');
        if (queryIndex >= 0) {
            path = path.substring(0, queryIndex);
        }
        if (path.isEmpty()) {
            path = "/";
        }
        // 百分号解码（用 URI 以保留 '+' 原样；失败说明已解码或含非法字符，退回原串）
        try {
            String decoded = URI.create(path).getPath();
            if (decoded != null && !decoded.isEmpty()) {
                path = decoded;
            }
        } catch (Exception ignored) {
            // 已经是解码后的形态
        }
        return foldDotSegments(path);
    }

    /**
     * 折叠路径里的 {@code .} / {@code ..} 段（RFC 3986 §5.2.4 的简化：绝对路径、超出根的 {@code ..} 丢弃）。
     *
     * <p><b>为什么必须折叠</b>：下游容器/路由会自行归一化路径——不折叠的话，uri 级 kid 白名单
     * 可被 {@code /x/../pay} 形态绕过（过滤器看到的是穿越形态、白名单不命中=不限 kid，下游却落到
     * 受保护资源）。解码后再折叠，{@code %2E%2E} 的编码形态一并覆盖；尾斜杠语义保留
     * （{@code /a/} → {@code /a/}，{@code /a/.} → {@code /a/}），合法客户端不受影响
     * （浏览器/HTTP 客户端发出请求前就已归一化路径）。
     */
    static String foldDotSegments(String path) {
        if (!path.startsWith("/") || !path.contains("/.")) {
            return path;
        }
        java.util.ArrayDeque<String> segments = new java.util.ArrayDeque<>();
        for (String segment : path.split("/", -1)) {
            if (segment.isEmpty() || segment.equals(".")) {
                continue;
            }
            if (segment.equals("..")) {
                if (!segments.isEmpty()) {
                    segments.pollLast();
                }
                continue;
            }
            segments.addLast(segment);
        }
        StringBuilder folded = new StringBuilder(path.length());
        for (String segment : segments) {
            folded.append('/').append(segment);
        }
        if (folded.length() == 0) {
            return "/";
        }
        boolean trailingSlash = path.endsWith("/") || path.endsWith("/.") || path.endsWith("/..");
        if (trailingSlash && folded.charAt(folded.length() - 1) != '/') {
            folded.append('/');
        }
        return folded.toString();
    }

    /** 归一化 HTTP 方法（大写）。 */
    public static String normalizeMethod(String method) {
        return method == null || method.isEmpty() ? "GET" : method.toUpperCase(Locale.ROOT);
    }

    /**
     * 构造要放进 JWE protected header 的绑上下文字段。
     *
     * @param ts 毫秒时间戳（与 {@link System#currentTimeMillis()} 同量纲）
     */
    public static Map<String, Object> claims(String uri, String method, Direction direction, long ts, String nonce) {
        Map<String, Object> claims = new LinkedHashMap<>(8);
        claims.put(CLAIM_URI, uri);
        claims.put(CLAIM_METHOD, normalizeMethod(method));
        claims.put(CLAIM_DIRECTION, direction.code());
        claims.put(CLAIM_TS, ts);
        claims.put(CLAIM_NONCE, nonce);
        return claims;
    }

    /**
     * 校验 protected header 里的上下文与本请求实际上下文一致。
     *
     * @throws EncryptorException 字段缺失或任一不一致（分类见 {@code EncryptorFailure.AAD_MISMATCH}）
     */
    public static void verify(Map<String, Object> header, String uri, String method, Direction direction) {
        Object headerUri = header.get(CLAIM_URI);
        Object headerMethod = header.get(CLAIM_METHOD);
        Object headerDirection = header.get(CLAIM_DIRECTION);
        if (headerUri == null || headerMethod == null || headerDirection == null) {
            throw new EncryptorException("AAD 上下文缺失: uri=" + headerUri + ", m=" + headerMethod
                + ", dir=" + headerDirection);
        }
        if (!String.valueOf(headerUri).equals(uri)) {
            throw new EncryptorException("AAD uri 不匹配: expected=" + uri + ", actual=" + headerUri);
        }
        String expectedMethod = normalizeMethod(method);
        if (!String.valueOf(headerMethod).equals(expectedMethod)) {
            throw new EncryptorException("AAD method 不匹配: expected=" + expectedMethod + ", actual=" + headerMethod);
        }
        if (!String.valueOf(headerDirection).equals(direction.code())) {
            throw new EncryptorException("AAD 方向不匹配: expected=" + direction.code() + ", actual=" + headerDirection);
        }
    }
}
