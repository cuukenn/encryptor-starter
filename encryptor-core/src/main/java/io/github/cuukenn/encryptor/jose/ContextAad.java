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
     * 规范化路径：去掉 contextPath、去掉 query、百分号解码、UTF-8。
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
        return path;
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
