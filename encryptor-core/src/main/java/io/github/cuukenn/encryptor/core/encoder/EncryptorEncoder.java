package io.github.cuukenn.encryptor.core.encoder;

import io.github.cuukenn.encryptor.core.EncoderStrategy;
import io.github.cuukenn.encryptor.core.EncryptorStrategy;
import io.github.cuukenn.encryptor.core.IEncryptorStrategy;

/**
 * @author changgg
 */
public class EncryptorEncoder implements IEncryptorStrategy<byte[], String> {
    private final EncryptorStrategy delegate;
    private final EncoderStrategy encoderStrategy;

    public EncryptorEncoder(EncryptorStrategy delegate, EncoderStrategy encoderStrategy) {
        this.delegate = delegate;
        this.encoderStrategy = encoderStrategy;
    }

    @Override
    public String encrypt(byte[] data) {
        return encoderStrategy.encode(delegate.encrypt(data));
    }

    @Override
    public byte[] decrypt(String data) {
        return delegate.decrypt(encoderStrategy.decode(data));
    }
}
