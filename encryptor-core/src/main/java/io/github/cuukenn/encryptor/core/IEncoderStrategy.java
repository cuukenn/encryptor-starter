package io.github.cuukenn.encryptor.core;

/**
 * @author changgg
 */
public interface IEncoderStrategy<I> {
    String encode(I data);

    I decode(String data);
}
