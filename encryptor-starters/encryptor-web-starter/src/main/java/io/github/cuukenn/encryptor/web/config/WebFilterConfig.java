package io.github.cuukenn.encryptor.web.config;

/**
 * servlet 侧过滤器链的 order 默认值。**顺序本身是载荷契约的一部分**（P2-5）：
 *
 * <pre>
 * -13 JWKS 发现端点  最外层
 * -12 门面过滤器     识别载体（query/JSON/form）、一次性解密、装载 WebContext
 * -11 请求参数过滤器 把 WebContext.parameters 变成请求参数视图
 * -10 请求体过滤器   把 WebContext.bodyPlaintext 变成请求体流视图
 *  -3 响应体过滤器   业务写完之后用同一把 CEK 回加密（必须比门面更靠内）
 * </pre>
 *
 * <p>只有门面过滤器读请求（{@code getParameter*} / {@code getInputStream}）；-11/-10 只消费它的结果。
 * 因此改动这里的默认值会**静默**改变行为：门面必须在两个视图过滤器之外，响应过滤器必须在门面内层
 * （否则读不到 CEK，响应变明文）。{@code FilterChainOrderTest} 直接从 {@code WebEncryptorConfiguration}
 * 取生产注册按 order 组装链来钉住该顺序，改默认值即红。</p>
 *
 * @author changgg
 */
public class WebFilterConfig {
    /**
     * JWKS 发现端点顺序（最外层，先于全部加密过滤器）
     */
    private int jwksFilterOrder = -13;
    /**
     * 门面过滤器顺序（识别载体 / 一次性解密 / 装载 WebContext）
     */
    private int encryptorFilterOrder = -12;
    /**
     * 请求参数过滤器顺序（只消费 WebContext，不读请求）
     */
    private int encryptorReqParamsFilterOrder = -11;
    /**
     * 请求体过滤器顺序（只消费 WebContext，不读请求）
     */
    private int encryptorReqBodyFilterOrder = -10;
    /**
     * 响应体过滤器顺序（在门面内层，链后回加密）
     */
    private int encryptorResFilterOrder = -3;

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
