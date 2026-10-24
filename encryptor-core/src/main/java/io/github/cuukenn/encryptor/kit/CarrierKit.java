package io.github.cuukenn.encryptor.kit;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 载体（query/JSON/form）的纯字符串编解码工具——wire-format 知识单点维护。
 *
 * <p>历史教训：QUERY 载体的 {@code +} 解码口径曾因两侧各写一份而分叉（servlet 按 form 语义
 * 解码、网关按 URI 语义保留，2026-10-23 才统一）。本类把 form 语义解码/URI 形态编码、
 * query 上的 jwe 判定、form body 的 jwe 提取收敛到 core，两侧门面只保留 I/O 装配。</p>
 *
 * <p>口径契约：QUERY/FORM 载体明文是 <b>form 语义</b>的 urlencoded 文本（空格编码为 {@code +}，
 * 与 {@code URLDecoder} 一致）；重建 URI query 时统一编码为 URI 形态（空格={@code %20}、
 * 字面 {@code +} 编码为 {@code %2B}）。非法编码抛 {@link IllegalArgumentException}，
 * 失败面映射（audit/状态码）由调用方决定。</p>
 *
 * @author changgg
 */
public final class CarrierKit {

    private CarrierKit() {
    }

    /** jwe 参数是否出现在 query string 上（name 支持百分号编码形态）。 */
    public static boolean hasQueryJwe(String queryString, String jweParam) {
        if (queryString == null || queryString.isEmpty()) {
            return false;
        }
        for (String pair : queryString.split("&")) {
            int index = pair.indexOf('=');
            String name = index < 0 ? pair : pair.substring(0, index);
            if (jweParam.equals(name)) {
                return true;
            }
            try {
                if (jweParam.equals(URLDecoder.decode(name, "UTF-8"))) {
                    return true;
                }
            } catch (IllegalArgumentException | UnsupportedEncodingException ignored) {
                // 非法编码交给后续解析路径处理
            }
        }
        return false;
    }

    /** form 语义解码单个组件（{@code +}=空格；非法转义抛 {@link IllegalArgumentException}）。 */
    public static String decodeFormComponent(String value) {
        try {
            return URLDecoder.decode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 必然存在", e);
        }
    }

    /** 编码为 URI query 形态：URLEncoder 的 {@code +}（空格）改写为 {@code %20}。 */
    public static String encodeQueryComponent(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 必然存在", e);
        }
    }

    /**
     * 按 form 语义解析 urlencoded 文本为参数视图（插入序、保留多值；name/value 均解码）。
     * 非法编码抛 {@link IllegalArgumentException}。
     */
    public static Map<String, List<String>> parseUrlencoded(String text) {
        Map<String, List<String>> collected = new LinkedHashMap<>();
        for (String pair : text.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int index = pair.indexOf('=');
            String name = index < 0 ? pair : pair.substring(0, index);
            String value = index < 0 ? "" : pair.substring(index + 1);
            collected.computeIfAbsent(decodeFormComponent(name), k -> new ArrayList<>())
                .add(decodeFormComponent(value));
        }
        return collected;
    }

    /** 从 form body 提取 jwe 字段值（无该字段/空 body 返回 {@code null}；解码失败返回 {@code null} 由失败面处理）。 */
    public static String jweFromFormBody(byte[] body, String jweParam) {
        if (body == null || body.length == 0) {
            return null;
        }
        String text = new String(body, StandardCharsets.UTF_8);
        String prefix = jweParam + "=";
        for (String field : text.split("&")) {
            if (field.startsWith(prefix)) {
                try {
                    return URLDecoder.decode(field.substring(prefix.length()), "UTF-8");
                } catch (Exception e) {
                    return null;
                }
            }
        }
        return null;
    }
}
