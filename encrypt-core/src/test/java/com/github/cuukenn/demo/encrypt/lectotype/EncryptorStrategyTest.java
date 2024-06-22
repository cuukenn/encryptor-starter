package com.github.cuukenn.demo.encrypt.lectotype;


import cn.hutool.crypto.asymmetric.AbstractAsymmetricCrypto;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.asymmetric.SM2;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.crypto.symmetric.SM4;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import com.github.cuukenn.demo.encrypt.lectotype.encoder.Base64Encoder;
import com.github.cuukenn.demo.encrypt.lectotype.encoder.EncryptorEncoder;
import com.github.cuukenn.demo.encrypt.lectotype.encryptor.HtlASymmetricCryptoEncryptor;
import com.github.cuukenn.demo.encrypt.lectotype.encryptor.HtlSymmetricCryptoEncryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * @author changgg
 */
public class EncryptorStrategyTest {
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
            Assertions.assertEquals(data, decrypt);
        }
    }
}