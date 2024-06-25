package io.github.cuukenn.encryptor.core.encoder;

import cn.hutool.core.codec.Base64;
import io.github.cuukenn.encryptor.core.EncoderStrategy;

/**
 * Base64编码
 *
 * @author changgg
 */
public class Base64Encoder implements EncoderStrategy {
    @Override
    public String encode(byte[] data) {
        return Base64.encode(data);
    }

    @Override
    public byte[] decode(String data) {
        return Base64.decode(data);
    }
}
