package io.github.cuukenn.encryptor.jose;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Concat KDF（NIST SP 800-56A §5.8.1）+ JOSE 的 OtherInfo 约定（RFC 7518 §4.6.2）——
 * ECDH-ES 从共享密钥 Z 派生 CEK。
 *
 * <p>OtherInfo = {@code AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo}，四项都带 4 字节大端长度前缀；
 * 本实现把 {@code AlgorithmID} 取 JWE 的 {@code enc} 值（RFC 7518 规定），
 * {@code PartyUInfo}/{@code PartyVInfo} 为空（不使用 {@code apu}/{@code apv}），
 * {@code SuppPubInfo} 为 keydatalen（比特，4 字节大端）。摘要固定 SHA-256。</p>
 *
 * <p>单轮足够：SHA-256 输出 32 字节 = 256 bit ≥ 本项目所有 {@code enc} 的密钥长度（128/192/256），
 * 因此 {@code 密钥长度 > 256 bit} 一律拒绝，而不是悄悄截断或补零。</p>
 *
 * @author changgg
 */
final class ConcatKdf {

    private static final String DIGEST = "SHA-256";
    private static final int DIGEST_BYTES = 32;
    private static final byte[] EMPTY = new byte[0];

    private ConcatKdf() {
    }

    /**
     * 派生 CEK。
     *
     * @param z              ECDH 共享密钥（P-256 上即 x 坐标，32 字节）
     * @param algorithmId    JOSE 里取 {@code enc}（如 {@code A256GCM}）
     * @param keyLengthBits  目标密钥长度（比特）
     * @return 长度 = {@code keyLengthBits/8} 的 CEK
     */
    static byte[] derive(byte[] z, String algorithmId, int keyLengthBits) {
        if (z == null || z.length == 0) {
            throw new IllegalArgumentException("ECDH 共享密钥不能为空");
        }
        if (algorithmId == null || algorithmId.isEmpty()) {
            throw new IllegalArgumentException("Concat KDF 的 AlgorithmID 不能为空");
        }
        if (keyLengthBits <= 0 || keyLengthBits > DIGEST_BYTES * 8) {
            throw new IllegalArgumentException("Concat KDF keydatalen 必须是 1..256 bit，实际: " + keyLengthBits);
        }
        byte[] algorithm = algorithmId.getBytes(StandardCharsets.US_ASCII);
        byte[] otherInfo = new byte[4 + algorithm.length + 4 + 4 + 4];
        int offset = putLengthPrefixed(otherInfo, 0, algorithm);
        offset = putLengthPrefixed(otherInfo, offset, EMPTY);
        offset = putLengthPrefixed(otherInfo, offset, EMPTY);
        putInt(otherInfo, offset, keyLengthBits);

        byte[] input = new byte[4 + z.length + otherInfo.length];
        putInt(input, 0, 1);
        System.arraycopy(z, 0, input, 4, z.length);
        System.arraycopy(otherInfo, 0, input, 4 + z.length, otherInfo.length);

        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(DIGEST);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JRE 不支持 " + DIGEST, e);
        }
        byte[] derived = digest.digest(input);
        if (derived.length * 8 != keyLengthBits) {
            byte[] trimmed = new byte[keyLengthBits / 8];
            System.arraycopy(derived, 0, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return derived;
    }

    private static int putLengthPrefixed(byte[] target, int offset, byte[] value) {
        putInt(target, offset, value.length);
        System.arraycopy(value, 0, target, offset + 4, value.length);
        return offset + 4 + value.length;
    }

    private static void putInt(byte[] target, int offset, int value) {
        target[offset] = (byte)(value >>> 24);
        target[offset + 1] = (byte)(value >>> 16);
        target[offset + 2] = (byte)(value >>> 8);
        target[offset + 3] = (byte)value;
    }
}
