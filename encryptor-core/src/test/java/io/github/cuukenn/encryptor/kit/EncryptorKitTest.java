package io.github.cuukenn.encryptor.kit;

import cn.hutool.crypto.digest.MD5;
import cn.hutool.crypto.symmetric.AES;
import io.github.cuukenn.encryptor.core.digester.HtlDigester;
import io.github.cuukenn.encryptor.core.encoder.Base64Encoder;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.core.encryptor.HtlSymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.signer.DigestWithEncryptSigner;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

/**
 * 报文缺字段时必须是可分类的 EncryptorException，而不是 NPE / 加密库异常
 * （畸形报文来自网络，调用方需要能区分"报文非法"与"服务端 bug"）。
 *
 * @author changgg
 */
public class EncryptorKitTest {
    private static final byte[] KEY = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8);

    private static EncryptorEncoder encryptorEncoder() {
        return new EncryptorEncoder(new HtlSymmetricCryptoEncryptor(new AES("CBC", "PKCS5Padding", KEY, IV)), new Base64Encoder());
    }

    private static SignerEncoder signerEncoder() {
        return new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()),
                new HtlSymmetricCryptoEncryptor(new AES("CBC", "PKCS5Padding", KEY, IV))), new Base64Encoder());
    }

    private static EncryptorDataWrapper validWrapper() {
        return EncryptorKit.encrypt(encryptorEncoder(), signerEncoder(), "hello".getBytes(StandardCharsets.UTF_8), "key");
    }

    @Test
    public void test_missing_timestamp_raises_encryptor_exception() {
        EncryptorDataWrapper wrapper = validWrapper();
        wrapper.setTimestamp(null);
        Assertions.assertThrows(EncryptorException.class, () -> EncryptorKit.decrypt(encryptorEncoder(), signerEncoder(), wrapper));
    }

    @Test
    public void test_missing_nonce_raises_encryptor_exception() {
        EncryptorDataWrapper wrapper = validWrapper();
        wrapper.setNonce(null);
        Assertions.assertThrows(EncryptorException.class, () -> EncryptorKit.decrypt(encryptorEncoder(), signerEncoder(), wrapper));
    }

    @Test
    public void test_missing_data_raises_encryptor_exception() {
        EncryptorDataWrapper wrapper = validWrapper();
        wrapper.setData(null);
        Assertions.assertThrows(EncryptorException.class, () -> EncryptorKit.decrypt(encryptorEncoder(), signerEncoder(), wrapper));
    }

    @Test
    public void test_missing_signature_raises_encryptor_exception() {
        EncryptorDataWrapper wrapper = validWrapper();
        wrapper.setSignature(null);
        Assertions.assertThrows(EncryptorException.class, () -> EncryptorKit.decrypt(encryptorEncoder(), signerEncoder(), wrapper));
    }
}
