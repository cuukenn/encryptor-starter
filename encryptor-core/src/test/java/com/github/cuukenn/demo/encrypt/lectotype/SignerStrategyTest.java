package com.github.cuukenn.demo.encrypt.lectotype;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.SignAlgorithm;
import com.github.cuukenn.demo.encrypt.lectotype.core.EncoderStrategy;
import com.github.cuukenn.demo.encrypt.lectotype.core.SignerStrategy;
import com.github.cuukenn.demo.encrypt.lectotype.core.encoder.Base64Encoder;
import com.github.cuukenn.demo.encrypt.lectotype.core.encoder.SignerEncoder;
import com.github.cuukenn.demo.encrypt.lectotype.core.signer.HtlSigner;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * @author changgg
 */
public class SignerStrategyTest {
    @Test
    public void test_hutool_digest() {
        List<SignAlgorithm> cryptos = Arrays.asList(
                SignAlgorithm.MD5withRSA,
                SignAlgorithm.SHA1withDSA
        );
        final byte[] data = "This Is A Test".getBytes(StandardCharsets.UTF_8);
        for (SignAlgorithm crypto : cryptos) {
            SignerStrategy signerStrategy = new HtlSigner(SecureUtil.sign(crypto));
            byte[] sig = signerStrategy.sign(data);
            boolean flag = signerStrategy.verify(sig, data);
            Assertions.assertTrue(flag);
        }
    }

    @Test
    public void test_hutool_digest_encoder() {
        List<SignAlgorithm> cryptos = Arrays.asList(
                SignAlgorithm.MD5withRSA,
                SignAlgorithm.SHA1withDSA
        );
        final String data = "This Is A Test";
        EncoderStrategy encoderStrategy = new Base64Encoder();
        for (SignAlgorithm crypto : cryptos) {
            SignerEncoder signerStrategy = new SignerEncoder(new HtlSigner(SecureUtil.sign(crypto)), encoderStrategy);
            String sig = signerStrategy.sign(data);
            System.out.println(sig);
            boolean flag = signerStrategy.verify(sig, data);
            Assertions.assertTrue(flag);
        }
    }
}