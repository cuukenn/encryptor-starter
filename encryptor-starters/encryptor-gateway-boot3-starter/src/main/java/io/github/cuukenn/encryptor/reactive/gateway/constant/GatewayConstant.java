package io.github.cuukenn.encryptor.reactive.gateway.constant;

/**
 * @author changgg
 */
public class GatewayConstant {
    /**
     * 跳过加密的请求头（仅 {@code skip-able=true} 时生效）。
     */
    public static final String SKIP_HEADER = "x-skip-encryptor";
    /**
     * 本次请求加解密上下文在 exchange attribute 里的键。
     */
    public static final String GATEWAY_CONTEXT_ATTR = "encryptor.gateway.context";
    public static final String JWE_PARAM = "jwe";
}
