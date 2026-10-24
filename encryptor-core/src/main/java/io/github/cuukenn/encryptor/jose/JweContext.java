package io.github.cuukenn.encryptor.jose;

import java.util.Arrays;

/**
 * 一次成功解密的请求上下文：明文、CEK（响应方向要用同一把）、以及绑定的元数据。
 *
 * @author changgg
 */
public final class JweContext {

    private final byte[] plaintext;
    private final byte[] cek;
    private final String kid;
    private final String alg;
    private final String enc;
    private final long ts;
    private final String nonce;
    private boolean destroyed;

    public JweContext(byte[] plaintext, byte[] cek, String kid, String alg, String enc, long ts, String nonce) {
        this.plaintext = plaintext;
        this.cek = cek;
        this.kid = kid;
        this.alg = alg;
        this.enc = enc;
        this.ts = ts;
        this.nonce = nonce;
    }

    /** 业务明文（请求参数或请求体）。 */
    public byte[] plaintext() {
        if (destroyed) {
            throw new IllegalStateException("JweContext 已销毁（plaintext 已清零）");
        }
        return plaintext;
    }

    /**
     * 内容加密密钥；响应方向用它以 {@code alg=dir} 加密。
     *
     * @throws IllegalStateException {@link #destroy()} 之后调用。全零数组是合法 AES 密钥，
     *                               静默返回会产出客户端必然解不开的报文且服务端无告警。
     */
    public byte[] cek() {
        if (destroyed) {
            throw new IllegalStateException("JweContext 已销毁（cek 已清零），不能再用于响应加密");
        }
        return cek;
    }

    public String kid() {
        return kid;
    }

    public String alg() {
        return alg;
    }

    public String enc() {
        return enc;
    }

    /** 客户端时间戳（毫秒）。 */
    public long ts() {
        return ts;
    }

    public String nonce() {
        return nonce;
    }

    /**
     * 请求生命周期结束时 best-effort 清零明文与 CEK。
     *
     * <p>只能降低堆转储/内存复用的暴露窗口，不能保证 JVM/GC 中没有副本。
     */
    public void destroy() {
        destroyed = true;
        if (plaintext != null) {
            Arrays.fill(plaintext, (byte) 0);
        }
        if (cek != null) {
            Arrays.fill(cek, (byte) 0);
        }
    }
}
