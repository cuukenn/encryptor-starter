package io.github.cuukenn.encryptor.reactive.configuration;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.digest.MD5;
import cn.hutool.crypto.symmetric.AES;
import io.github.cuukenn.encryptor.core.digester.HtlDigester;
import io.github.cuukenn.encryptor.core.encoder.Base64Encoder;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.core.encryptor.HtlSymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.signer.DigestWithEncryptSigner;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.kit.EncryptorKit;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.config.CryptoConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

/**
 * 校验 reactive 侧默认工厂与"前端契约"一致：key 字段是 16 字节 AES 密钥的 Base64 文本，
 * iv 是 16 字符原文 —— 也就是 servlet 侧与 encryptor-examples 前端 JS 共同遵循的约定。
 *
 * @author changgg
 */
public class EncryptorReactiveAutoConfigurationTest {
    private static final String ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String MODE = "CBC";
    private static final String PADDING = "PKCS5Padding";

    @Test
    public void test_decrypt_payload_built_by_front_end() {
        RSA keyPair = new RSA();
        CryptoConfig config = new CryptoConfig();
        config.setAlgorithm(ALGORITHM);
        config.setPrivateKey(keyPair.getPrivateKeyBase64());
        config.setPublicKey(keyPair.getPublicKeyBase64());

        EncryptorFacade facade = new EncryptorReactiveAutoConfiguration()
                .encryptorFacadeFactory(Collections.emptyList())
                .apply(config);

        // 前端 encryptor/aes.js：generateBase64Key(128)=btoa(16 字符)，取用时 CryptoJS.enc.Base64.parse(key) 还原成 16 字节
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        String iv = "abcdefghijklmnop";
        String params = "{\"mode\":\"" + MODE + "\",\"padding\":\"" + PADDING + "\",\"key\":\"" + Base64.encode(key) + "\",\"iv\":\"" + iv + "\"}";
        String keyField = new RSA(ALGORITHM, null, keyPair.getPublicKeyBase64()).encryptBase64(params, KeyType.PublicKey);

        // 客户端按同一契约加密业务数据并对 (nonce + timestamp + data) 签名
        HtlSymmetricCryptoEncryptor crypto = new HtlSymmetricCryptoEncryptor(new AES(MODE, PADDING, key, iv.getBytes(StandardCharsets.UTF_8)));
        EncryptorEncoder encryptorEncoder = new EncryptorEncoder(crypto, new Base64Encoder());
        SignerEncoder signerEncoder = new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()), crypto), new Base64Encoder());
        EncryptorDataWrapper wrapper = EncryptorKit.encrypt(encryptorEncoder, signerEncoder, "hello".getBytes(StandardCharsets.UTF_8), keyField);

        Assertions.assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), facade.decrypt(wrapper));
    }
}
