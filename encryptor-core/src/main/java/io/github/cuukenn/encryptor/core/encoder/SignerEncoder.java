package io.github.cuukenn.encryptor.core.encoder;

import io.github.cuukenn.encryptor.core.EncoderStrategy;
import io.github.cuukenn.encryptor.core.SignerStrategy;
import io.github.cuukenn.encryptor.core.ISignerStrategy;

import java.nio.charset.StandardCharsets;

/**
 * @author changgg
 */
public class SignerEncoder implements ISignerStrategy<String, String> {
    private final SignerStrategy delegate;
    private final EncoderStrategy encoderStrategy;

    public SignerEncoder(SignerStrategy delegate, EncoderStrategy encoderStrategy) {
        this.delegate = delegate;
        this.encoderStrategy = encoderStrategy;
    }

    @Override
    public boolean verify(String signature, String data) {
        return delegate.verify(encoderStrategy.decode(signature), data.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String sign(String data) {
        return encoderStrategy.encode(delegate.sign(data.getBytes(StandardCharsets.UTF_8)));
    }
}
