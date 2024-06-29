package io.github.cuukenn.encryptor.reactive.gateway.config;

import org.springframework.cloud.gateway.filter.NettyWriteResponseFilter;

/**
 * @author changgg
 */
public class GatewayFilterConfig {
    /**
     * 门面加密过滤器顺序
     */
    private int encryptorFilterOrder = -12;
    /**
     * 请求参数过滤器顺序
     */
    private int encryptorReqParamsFilterOrder = -11;
    /**
     * 请求体过滤器顺序
     */
    private int encryptorReqBodyFilterOrder = -10;
    /**
     * 响应体过滤器顺序
     */
    private int encryptorResFilterOrder = NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1;

    public int getEncryptorFilterOrder() {
        return encryptorFilterOrder;
    }

    public void setEncryptorFilterOrder(int encryptorFilterOrder) {
        this.encryptorFilterOrder = encryptorFilterOrder;
    }

    public int getEncryptorReqParamsFilterOrder() {
        return encryptorReqParamsFilterOrder;
    }

    public void setEncryptorReqParamsFilterOrder(int encryptorReqParamsFilterOrder) {
        this.encryptorReqParamsFilterOrder = encryptorReqParamsFilterOrder;
    }

    public int getEncryptorReqBodyFilterOrder() {
        return encryptorReqBodyFilterOrder;
    }

    public void setEncryptorReqBodyFilterOrder(int encryptorReqBodyFilterOrder) {
        this.encryptorReqBodyFilterOrder = encryptorReqBodyFilterOrder;
    }

    public int getEncryptorResFilterOrder() {
        return encryptorResFilterOrder;
    }

    public void setEncryptorResFilterOrder(int encryptorResFilterOrder) {
        this.encryptorResFilterOrder = encryptorResFilterOrder;
    }
}
