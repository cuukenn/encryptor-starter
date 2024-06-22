package com.github.cuukenn.demo.encrypt.lectotype.encryptor;

import cn.hutool.crypto.symmetric.SymmetricCrypto;
import com.github.cuukenn.demo.encrypt.lectotype.EncryptorStrategy;

import java.util.function.Supplier;

/**
 * hutool的对称加解密实现
 *
 * @author changgg
 */
public class HtlSymmetricCryptoEncryptor implements EncryptorStrategy {
    protected final SymmetricCrypto encryptor;

    public HtlSymmetricCryptoEncryptor(SymmetricCrypto encryptor) {
        this.encryptor = encryptor;
    }

    public HtlSymmetricCryptoEncryptor(Supplier<SymmetricCrypto> encryptor) {
        this.encryptor = encryptor.get();
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return encryptor.encrypt(data);
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return encryptor.decrypt(data);
    }
}
