package io.github.cuukenn.encryptor.jose;

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
        return plaintext;
    }

    /** 内容加密密钥；响应方向用它以 {@code alg=dir} 加密。 */
    public byte[] cek() {
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
}
