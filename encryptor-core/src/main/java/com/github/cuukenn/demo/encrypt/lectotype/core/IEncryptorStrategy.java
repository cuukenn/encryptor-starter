package com.github.cuukenn.demo.encrypt.lectotype.core;

/**
 * @author changgg
 */
public interface IEncryptorStrategy<I, O> {
    /**
     * 加密
     *
     * @return 密文
     */
    O encrypt(I data);

    /**
     * 解密
     *
     * @return 明文
     */
    I decrypt(O data);
}
