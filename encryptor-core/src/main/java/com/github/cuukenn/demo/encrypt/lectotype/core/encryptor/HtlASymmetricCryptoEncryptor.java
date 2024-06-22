package com.github.cuukenn.demo.encrypt.lectotype.core.encryptor;

import cn.hutool.crypto.asymmetric.AbstractAsymmetricCrypto;
import cn.hutool.crypto.asymmetric.KeyType;
import com.github.cuukenn.demo.encrypt.lectotype.core.EncryptorStrategy;

import java.util.function.Supplier;

/**
 * hutool的非对称加解密实现
 *
 * @author changgg
 */
public class HtlASymmetricCryptoEncryptor implements EncryptorStrategy {
    protected final AbstractAsymmetricCrypto<?> encryptor;

    public HtlASymmetricCryptoEncryptor(AbstractAsymmetricCrypto<?> encryptor) {
        this.encryptor = encryptor;
    }

    public HtlASymmetricCryptoEncryptor(Supplier<AbstractAsymmetricCrypto<?>> encryptor) {
        this.encryptor = encryptor.get();
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return encryptor.encrypt(data, KeyType.PublicKey);
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return encryptor.decrypt(data, KeyType.PrivateKey);
    }
}
