package io.github.cuukenn.encryptor.reactive.gateway.kit;

import io.github.cuukenn.encryptor.jose.JweContext;

import java.util.Arrays;

/**
 * 单次请求的加解密上下文（存 exchange attribute，无 ThreadLocal —— reactive 线程会跳）。
 *
 * @author changgg
 */
public class GatewayContext {
    /**
     * 报文载体：无 / query / JSON body / form body。
     */
    public enum Carrier {
        NONE, QUERY, JSON, FORM
    }

    private Carrier carrier = Carrier.NONE;
    private JweContext jweContext;
    private byte[] plaintextBody;
    private boolean encrypted;

    public Carrier getCarrier() {
        return carrier;
    }

    public void setCarrier(Carrier carrier) {
        this.carrier = carrier;
    }

    public JweContext getJweContext() {
        return jweContext;
    }

    public void setJweContext(JweContext jweContext) {
        this.jweContext = jweContext;
    }

    public byte[] getPlaintextBody() {
        return plaintextBody;
    }

    public void setPlaintextBody(byte[] plaintextBody) {
        this.plaintextBody = plaintextBody;
    }

    public boolean isEncrypted() {
        return encrypted;
    }

    public void setEncrypted(boolean encrypted) {
        this.encrypted = encrypted;
    }

    /**
     * 请求生命周期结束时 best-effort 清零明文与 CEK，并断开引用。
     */
    public void destroy() {
        if (jweContext != null) {
            jweContext.destroy();
        }
        if (plaintextBody != null) {
            Arrays.fill(plaintextBody, (byte) 0);
        }
        jweContext = null;
        plaintextBody = null;
    }
}
