package io.github.cuukenn.encryptor.core.encoder;

import io.github.cuukenn.encryptor.core.EncoderStrategy;
import io.github.cuukenn.encryptor.core.ISignerStrategy;
import io.github.cuukenn.encryptor.core.SignerStrategy;

/**
 * @author changgg
 */
public class SignerEncoder implements ISignerStrategy<String, byte[]> {
    private final SignerStrategy delegate;
    private final EncoderStrategy encoderStrategy;

    public SignerEncoder(SignerStrategy delegate, EncoderStrategy encoderStrategy) {
        this.delegate = delegate;
        this.encoderStrategy = encoderStrategy;
    }

    @Override
    public boolean verify(String signature, byte[] data) {
        return delegate.verify(encoderStrategy.decode(signature), data);
    }

    @Override
    public String sign(byte[] data) {
        return encoderStrategy.encode(delegate.sign(data));
    }
}
