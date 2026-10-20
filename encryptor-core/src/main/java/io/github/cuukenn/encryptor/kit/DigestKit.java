package io.github.cuukenn.encryptor.kit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 摘要工具：JWKS ETag、公钥指纹等纯计算逻辑，避免 servlet/reactive 两侧各写一份。
 *
 * @author changgg
 */
public final class DigestKit {

    private DigestKit() {
    }

    /** SHA-256 的十六进制小写表示。 */
    public static String sha256Hex(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM 不支持 SHA-256", e);
        }
    }

    /** 文本按 UTF-8 计算 SHA-256 的十六进制小写表示。 */
    public static String sha256Hex(String text) {
        return sha256Hex(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 公钥指纹：SPKI Base64 文本的 SHA-256 前 6 字节（12 位 hex），用于启动摘要与运维核对。
     */
    public static String fingerprint(String spkiBase64) {
        String hex = sha256Hex(spkiBase64.getBytes(StandardCharsets.US_ASCII));
        return hex.substring(0, 12);
    }
}
