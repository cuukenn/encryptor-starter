package io.github.cuukenn.encryptor.constant;

/**
 * @author changgg
 */
public class EncryptorConstant {
    /**
     * v2 报文载体字段名：请求 query/JSON/form 与响应 JSON 里唯一的参数名。
     */
    public static final String JWE_PARAM = "jwe";

    /**
     * 失败响应的排障标识头：值与日志里的 trace 对应，便于把一次失败请求对到服务端日志。
     */
    public static final String TRACE_HEADER = "X-Encryptor-Trace";
}
