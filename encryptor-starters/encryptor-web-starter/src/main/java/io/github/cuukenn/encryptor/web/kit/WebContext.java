package io.github.cuukenn.encryptor.web.kit;

import cn.hutool.core.thread.ThreadUtil;
import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;

import java.util.Map;

/**
 * 一次请求内的解密结果与配置上下文（门面过滤器写入，下游过滤器/转换器只读消费）。
 *
 * @author changgg
 */
public class WebContext {
    /**
     * jwe 载体形态。
     */
    public enum Carrier {
        /**
         * 非加密请求（透传）。
         */
        NONE,
        /**
         * query 参数 {@code ?jwe=…}，明文是 urlencoded 文本。
         */
        QUERY,
        /**
         * JSON body {@code {"jwe":"…"}}，明文是业务 JSON。
         */
        JSON,
        /**
         * form 字段 {@code jwe=…}，明文既是 urlencoded 文本（参数视图）也是 body。
         */
        FORM
    }

    private static final ThreadLocal<WebContext> CONTEXT = ThreadUtil.createThreadLocal(WebContext::new);
    private boolean reqEncryptor;
    private JweContext jweContext;
    private Carrier carrier = Carrier.NONE;
    private byte[] bodyPlaintext;
    private Map<String, String[]> parameters;
    private WebEncryptorConfig config;
    private EncryptorConfig protocol;

    public boolean isReqEncryptor() {
        return reqEncryptor;
    }

    public void setReqEncryptor(boolean reqEncryptor) {
        this.reqEncryptor = reqEncryptor;
    }

    public JweContext getJweContext() {
        return jweContext;
    }

    public void setJweContext(JweContext jweContext) {
        this.jweContext = jweContext;
    }

    public Carrier getCarrier() {
        return carrier;
    }

    public void setCarrier(Carrier carrier) {
        this.carrier = carrier;
    }

    public byte[] getBodyPlaintext() {
        return bodyPlaintext;
    }

    public void setBodyPlaintext(byte[] bodyPlaintext) {
        this.bodyPlaintext = bodyPlaintext;
    }

    public Map<String, String[]> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String[]> parameters) {
        this.parameters = parameters;
    }

    public WebEncryptorConfig getConfig() {
        return config;
    }

    public void setConfig(WebEncryptorConfig config) {
        this.config = config;
    }

    public EncryptorConfig getProtocol() {
        return protocol;
    }

    public void setProtocol(EncryptorConfig protocol) {
        this.protocol = protocol;
    }

    public static WebContext current() {
        return CONTEXT.get();
    }

    public static void clear() {
        CONTEXT.remove();
    }

    /**
     * 报文非法时的 HTTP 状态码；上下文未初始化时退回 400。
     */
    public static int failureStatus() {
        EncryptorConfig protocol = current().protocol;
        return protocol == null ? 400 : protocol.getFailureStatus();
    }

    /**
     * 请求体大小上限（字节）；{@code <= 0} 表示不限；上下文未初始化时按不限处理。
     */
    public static long maxRequestSize() {
        EncryptorConfig protocol = current().protocol;
        return protocol == null ? 0L : protocol.getMaxRequestSize();
    }

    /**
     * 命中范围的请求是否必须携带合法 jwe；上下文未初始化时按必须处理（fail-closed）。
     */
    public static boolean requireEncrypted() {
        EncryptorConfig protocol = current().protocol;
        return protocol == null || protocol.isRequireEncrypted();
    }
}
