package io.github.cuukenn.encryptor.reactive.gateway.config;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.NettyWriteResponseFilter;

/**
 * 两个 {@link GlobalFilter} 的 order（v1 五过滤器合并为二后只剩两条）。
 *
 * @author changgg
 */
public class GatewayFilterConfig {
    /**
     * 请求过滤器（决策 + 一次解密）order，最外层。
     */
    private int encryptorFilterOrder = -13;
    /**
     * 响应过滤器（加密回写）order，包住业务、在 NettyWrite 之内。
     */
    private int encryptorResFilterOrder = NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1;
    /**
     * JWKS 发现端点 order，比请求过滤器更外层（免加密路径先于一切加密逻辑）。
     */
    private int jwksFilterOrder = -14;

    public int getJwksFilterOrder() {
        return jwksFilterOrder;
    }

    public void setJwksFilterOrder(int jwksFilterOrder) {
        this.jwksFilterOrder = jwksFilterOrder;
    }

    public int getEncryptorFilterOrder() {
        return encryptorFilterOrder;
    }

    public void setEncryptorFilterOrder(int encryptorFilterOrder) {
        this.encryptorFilterOrder = encryptorFilterOrder;
    }

    public int getEncryptorResFilterOrder() {
        return encryptorResFilterOrder;
    }

    public void setEncryptorResFilterOrder(int encryptorResFilterOrder) {
        this.encryptorResFilterOrder = encryptorResFilterOrder;
    }
}
