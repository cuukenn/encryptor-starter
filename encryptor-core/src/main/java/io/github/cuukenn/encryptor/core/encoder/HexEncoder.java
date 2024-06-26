package io.github.cuukenn.encryptor.core.encoder;

import cn.hutool.core.util.HexUtil;
import io.github.cuukenn.encryptor.core.EncoderStrategy;

/**
 * hex编码格式
 *
 * @author changgg
 */
public class HexEncoder implements EncoderStrategy {
    @Override
    public String encode(byte[] data) {
        return HexUtil.encodeHexStr(data);
    }

    @Override
    public byte[] decode(String data) {
        return HexUtil.decodeHex(data);
    }
}
