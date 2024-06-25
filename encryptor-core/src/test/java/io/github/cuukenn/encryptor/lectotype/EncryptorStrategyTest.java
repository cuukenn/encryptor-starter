package io.github.cuukenn.encryptor.lectotype;


import cn.hutool.crypto.asymmetric.AbstractAsymmetricCrypto;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.asymmetric.SM2;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.crypto.symmetric.SM4;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import io.github.cuukenn.encryptor.core.EncoderStrategy;
import io.github.cuukenn.encryptor.core.EncryptorStrategy;
import io.github.cuukenn.encryptor.core.encoder.Base64Encoder;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encryptor.GroupEncryptor;
import io.github.cuukenn.encryptor.core.encryptor.HtlASymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.encryptor.HtlSymmetricCryptoEncryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * @author changgg
 */
public class EncryptorStrategyTest {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorStrategyTest.class);

    @Test
    public void test_hutool_sc_encryptor() {
        List<SymmetricCrypto> cryptos = Arrays.asList(
                new AES(),
                new SM4()
        );
        final byte[] data = "This Is A Test".getBytes(StandardCharsets.UTF_8);
        for (SymmetricCrypto crypto : cryptos) {
            EncryptorStrategy encryptorStrategy = new HtlSymmetricCryptoEncryptor(crypto);
            byte[] encrypt = encryptorStrategy.encrypt(data);
            byte[] decrypt = encryptorStrategy.decrypt(encrypt);
            Assertions.assertArrayEquals(data, decrypt);
        }
    }

    @Test
    public void test_hutool_asc_encryptor() {
        List<AbstractAsymmetricCrypto<?>> cryptos = Arrays.asList(
                new RSA(),
                new SM2()
        );
        final byte[] data = "This Is A Test".getBytes(StandardCharsets.UTF_8);
        for (AbstractAsymmetricCrypto<?> crypto : cryptos) {
            EncryptorStrategy encryptorStrategy = new HtlASymmetricCryptoEncryptor(crypto);
            byte[] encrypt = encryptorStrategy.encrypt(data);
            byte[] decrypt = encryptorStrategy.decrypt(encrypt);
            Assertions.assertArrayEquals(data, decrypt);
        }
    }

    @Test
    public void test_hutool_sc_encryptor_encoder() {
        List<SymmetricCrypto> cryptos = Arrays.asList(
                new AES(),
                new SM4()
        );
        final String data = "This Is A Test";
        EncoderStrategy encoderStrategy = new Base64Encoder();
        for (SymmetricCrypto crypto : cryptos) {
            EncryptorEncoder encryptorEncoder = new EncryptorEncoder(new HtlSymmetricCryptoEncryptor(crypto), encoderStrategy);
            String encrypt = encryptorEncoder.encrypt(data);
            String decrypt = encryptorEncoder.decrypt(encrypt);
            logger.info(encrypt);
            Assertions.assertEquals(data, decrypt);
        }
    }

    @Test
    public void test_hutool_sc_encryptor_groupEncoder() {
        List<SymmetricCrypto> cryptos = Arrays.asList(
                new AES(),
                new SM4()
        );
        final String data = "This Is A Test";
        EncoderStrategy encoderStrategy = new Base64Encoder();
        for (SymmetricCrypto crypto : cryptos) {
            EncryptorEncoder encryptorEncoder = new EncryptorEncoder(new HtlSymmetricCryptoEncryptor(crypto), encoderStrategy);
            GroupEncryptor groupEncryptor = new GroupEncryptor(encryptorEncoder, 4);
            String encrypt = groupEncryptor.encrypt(data);
            String decrypt = groupEncryptor.decrypt(encrypt);
            Assertions.assertEquals(data, decrypt);
        }
    }
}