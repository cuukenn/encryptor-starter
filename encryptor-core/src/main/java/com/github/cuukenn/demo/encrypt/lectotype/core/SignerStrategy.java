package com.github.cuukenn.demo.encrypt.lectotype.core;

/**
 * @author changgg
 */
public interface SignerStrategy extends ISignerStrategy<byte[], byte[]> {
    /**
     * 验证签名
     *
     * @return 校验结果
     */
    boolean verify(byte[] signature, byte[] data);

    /**
     * 签名
     *
     * @return 签名
     */
    byte[] sign(byte[] data);
}
