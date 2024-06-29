package io.github.cuukenn.encryptor.lectotype;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.SignAlgorithm;
import cn.hutool.crypto.digest.MD5;
import cn.hutool.crypto.symmetric.AES;
import io.github.cuukenn.encryptor.core.EncoderStrategy;
import io.github.cuukenn.encryptor.core.SignerStrategy;
import io.github.cuukenn.encryptor.core.digester.HtlDigester;
import io.github.cuukenn.encryptor.core.encoder.Base64Encoder;
import io.github.cuukenn.encryptor.core.encoder.HexEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.core.encryptor.HtlSymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.signer.DigestWithEncryptSigner;
import io.github.cuukenn.encryptor.core.signer.HtlSigner;
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
            String sig = signerStrategy.sign(data.getBytes());
            System.out.println(sig);
            boolean flag = signerStrategy.verify(sig, data.getBytes());
            Assertions.assertTrue(flag);
        }
    }

    @Test
    public void test_hutool_digest_encoder_hex() {
        List<SignAlgorithm> cryptos = Arrays.asList(
                SignAlgorithm.MD5withRSA,
                SignAlgorithm.SHA1withDSA
        );
        final String data = "This Is A Test";
        EncoderStrategy encoderStrategy = new HexEncoder();
        for (SignAlgorithm crypto : cryptos) {
            SignerEncoder signerStrategy = new SignerEncoder(new HtlSigner(SecureUtil.sign(crypto)), encoderStrategy);
            String sig = signerStrategy.sign(data.getBytes());
            System.out.println(sig);
            boolean flag = signerStrategy.verify(sig, data.getBytes());
            Assertions.assertTrue(flag);
        }
    }

    @Test
    public void test_hutool_digest_encoder_hex_with_aes() {
        final String data = "This Is A Test";
        EncoderStrategy encoderStrategy = new HexEncoder();
        SignerEncoder signerStrategy = new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()), new HtlSymmetricCryptoEncryptor(new AES())), encoderStrategy);
        String sig = signerStrategy.sign(data.getBytes());
        System.out.println(sig);
        boolean flag = signerStrategy.verify(sig, data.getBytes());
        Assertions.assertTrue(flag);
    }
}