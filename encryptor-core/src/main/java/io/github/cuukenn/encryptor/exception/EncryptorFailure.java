package io.github.cuukenn.encryptor.exception;

/**
 * 报文失败分类。仅用于日志、指标与排障：<b>对外仍是统一的 {@code failure-status} 与通用文案</b>，
 * 不把分类暴露给调用方（避免变成 oracle）。
 *
 * @author changgg
 */
public enum EncryptorFailure {

    /** 命中加密范围但报文里没有 {@code jwe} 字段。 */
    MISSING,
    /** JWE 结构或 protected header 非法（解析失败、算法/加密方法缺失、绑上下文字段缺失或类型不对）。 */
    BAD_HEADER,
    /** {@code kid} 缺失或未在服务端密钥库中。 */
    UNKNOWN_KID,
    /** {@code alg} 不在服务端白名单。 */
    ALG_NOT_ALLOWED,
    /** {@code enc} 不在服务端白名单。 */
    ENC_NOT_ALLOWED,
    /** 上下文（uri/method/方向）与密文绑定的不一致。 */
    AAD_MISMATCH,
    /** 解封 CEK 或 AEAD 校验失败（含被篡改）。 */
    DECRYPT_FAILED,
    /** 时间戳超出允许窗口。 */
    EXPIRED,
    /** nonce 已被使用过。 */
    REPLAY,
    /** 报文超过大小上限。 */
    TOO_LARGE,
    /** 封装响应失败。 */
    ENCRYPT_FAILED,
    /** 其它内部错误。 */
    INTERNAL
}
