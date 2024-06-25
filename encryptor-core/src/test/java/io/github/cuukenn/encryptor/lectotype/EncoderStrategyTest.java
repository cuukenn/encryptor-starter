package io.github.cuukenn.encryptor.lectotype;

import io.github.cuukenn.encryptor.core.EncoderStrategy;
import io.github.cuukenn.encryptor.core.encoder.Base64Encoder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

/**
 * @author changgg
 */
public class EncoderStrategyTest {
    @Test
    public void test_encoder_base64() {
        EncoderStrategy encoderStrategy = new Base64Encoder();
        final byte[] data = "This Is A Test".getBytes(StandardCharsets.UTF_8);
        String encode = encoderStrategy.encode(data);
        byte[] decode = encoderStrategy.decode(encode);
        Assertions.assertArrayEquals(data, decode);
    }
}