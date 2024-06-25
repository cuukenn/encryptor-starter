package io.github.cuukenn.encryptor.core.encoder;

import io.github.cuukenn.encryptor.core.EncoderStrategy;
import io.github.cuukenn.encryptor.core.EncryptorStrategy;
import io.github.cuukenn.encryptor.core.IEncryptorStrategy;

import java.nio.charset.StandardCharsets;

/**
 * @author changgg
 */
public class EncryptorEncoder implements IEncryptorStrategy<String, String> {
    private final EncryptorStrategy delegate;
    private final EncoderStrategy encoderStrategy;

    public EncryptorEncoder(EncryptorStrategy delegate, EncoderStrategy encoderStrategy) {
        this.delegate = delegate;
        this.encoderStrategy = encoderStrategy;
    }

    @Override
    public String encrypt(String data) {
        return encoderStrategy.encode(delegate.encrypt(data.getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    public String decrypt(String data) {
        return new String(delegate.decrypt(encoderStrategy.decode(data)), StandardCharsets.UTF_8);
    }
}
