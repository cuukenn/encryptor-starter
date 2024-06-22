package com.github.cuukenn.demo.encrypt.lectotype.core.signer;

import cn.hutool.crypto.asymmetric.Sign;
import com.github.cuukenn.demo.encrypt.lectotype.core.SignerStrategy;

import java.util.function.Supplier;

/**
 * hutool的对称加解密实现
 *
 * @author changgg
 */
public class HtlSigner implements SignerStrategy {
    protected final Sign sign;

    public HtlSigner(Sign sign) {
        this.sign = sign;
    }

    public HtlSigner(Supplier<Sign> sign) {
        this.sign = sign.get();
    }

    @Override
    public boolean verify(byte[] signature, byte[] data) {
        return sign.verify(data, signature);
    }

    @Override
    public byte[] sign(byte[] data) {
        return sign.sign(data);
    }
}
