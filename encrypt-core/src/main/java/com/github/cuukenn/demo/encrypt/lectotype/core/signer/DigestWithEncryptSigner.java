package com.github.cuukenn.demo.encrypt.lectotype.signer;

import com.github.cuukenn.demo.encrypt.lectotype.DigesterStrategy;
import com.github.cuukenn.demo.encrypt.lectotype.EncryptorStrategy;
import com.github.cuukenn.demo.encrypt.lectotype.SignerStrategy;

import java.util.Arrays;
import java.util.function.Supplier;

/**
 * 加密算法包裹数据的哈希值，而不用标准签名的那一套
 *
 * @author changgg
 */
public class DigestWithEncryptSigner implements SignerStrategy {
    private final DigesterStrategy digesterStrategy;
    private final EncryptorStrategy encryptorStrategy;

    public DigestWithEncryptSigner(DigesterStrategy digesterStrategy, EncryptorStrategy encryptorStrategy) {
        this.digesterStrategy = digesterStrategy;
        this.encryptorStrategy = encryptorStrategy;
    }

    public DigestWithEncryptSigner(Supplier<DigesterStrategy> digesterStrategy, Supplier<EncryptorStrategy> encryptorStrategy) {
        this.digesterStrategy = digesterStrategy.get();
        this.encryptorStrategy = encryptorStrategy.get();
    }

    @Override
    public boolean verify(byte[] signature, byte[] data) {
        final byte[] digest = digesterStrategy.digest(data);
        final byte[] decryptSig = encryptorStrategy.decrypt(signature);
        return Arrays.equals(digest, decryptSig);
    }

    @Override
    public byte[] sign(byte[] data) {
        final byte[] digest = digesterStrategy.digest(data);
        return encryptorStrategy.encrypt(digest);
    }
}
