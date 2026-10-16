package io.github.cuukenn.encryptor.jose;

/**
 * 报文方向：请求 / 响应。参与 AAD 绑定，防止"把请求密文当响应"之类的搬运。
 *
 * @author changgg
 */
public enum Direction {

    /** 客户端 → 服务端。 */
    REQUEST("req"),
    /** 服务端 → 客户端。 */
    RESPONSE("res");

    private final String code;

    Direction(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }

    public static Direction fromCode(String code) {
        for (Direction value : values()) {
            if (value.code.equals(code)) {
                return value;
            }
        }
        throw new IllegalArgumentException("未知方向: " + code);
    }
}
