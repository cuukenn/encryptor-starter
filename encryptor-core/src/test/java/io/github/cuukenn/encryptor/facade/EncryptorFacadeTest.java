package io.github.cuukenn.encryptor.facade;

import cn.hutool.crypto.CryptoException;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.digest.MD5;
import cn.hutool.crypto.symmetric.AES;
import io.github.cuukenn.encryptor.core.digester.HtlDigester;
import io.github.cuukenn.encryptor.core.encoder.Base64Encoder;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.core.encryptor.HtlASymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.encryptor.HtlSymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.signer.DigestWithEncryptSigner;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.kit.EncryptorKit;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 入口拦截 + 错误面统一：
 * 缺失字段、密钥不可用、报文解不开，对调用方都必须是可分类的 EncryptorException，
 * 而不是 NPE / hutool 的 CryptoException（攻击者可以据此区分失败原因，见 security-review.md S15）。
 *
 * @author changgg
 */
public class EncryptorFacadeTest {
    private static final byte[] KEY = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8);
    private static final String PARAMS = "{\"mode\":\"CBC\",\"padding\":\"PKCS5Padding\","
            + "\"key\":\"MDEyMzQ1Njc4OWFiY2RlZg==\",\"iv\":\"abcdefghijklmnop\"}";

    @Test
    public void test_missing_key_raises_encryptor_exception() {
        EncryptorFacade facade = new EncryptorFacade(
                new EncryptorEncoder(new HtlASymmetricCryptoEncryptor(new RSA()), new Base64Encoder()),
                params -> null, params -> null, Collections.emptyList());

        EncryptorDataWrapper wrapper = new EncryptorDataWrapper("nonce", 1L, "sig", null, "data");
        Assertions.assertThrows(EncryptorException.class, () -> facade.decrypt(wrapper));
    }

    @Test
    public void test_encrypt_with_missing_key_raises_encryptor_exception() {
        EncryptorFacade facade = new EncryptorFacade(
                new EncryptorEncoder(new HtlASymmetricCryptoEncryptor(new RSA()), new Base64Encoder()),
                params -> null, params -> null, Collections.emptyList());

        // 明文请求（没有协商过 key）走到响应加密时，缺 key 必须是可分类异常，而不是 RSA/NPE
        Assertions.assertThrows(EncryptorException.class,
                () -> facade.encrypt("hello".getBytes(StandardCharsets.UTF_8), null));
    }

    /**
     * 篡改 signature 时，hutool 会在 AES 解密阶段抛 CryptoException（长度/填充错误），
     * 调用方看到的是"内部错误"而不是"报文非法"————这正是 S15 说的审计信号丢失。
     */
    @Test
    public void test_tampered_signature_raises_encryptor_exception_with_crypto_cause() {
        RSA rsa = new RSA();
        AES aes = new AES("CBC", "PKCS5Padding", KEY, IV);
        String negotiatedKey = rsa.encryptBase64(PARAMS, KeyType.PublicKey);

        EncryptorFacade facade = new EncryptorFacade(
                new EncryptorEncoder(new HtlASymmetricCryptoEncryptor(rsa), new Base64Encoder()),
                params -> new EncryptorEncoder(new HtlSymmetricCryptoEncryptor(aes), new Base64Encoder()),
                params -> new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()),
                        new HtlSymmetricCryptoEncryptor(aes)), new Base64Encoder()),
                Collections.emptyList());

        EncryptorDataWrapper wrapper = EncryptorKit.encrypt(
                facade.getEncryptorEncoder().apply(PARAMS), facade.getSignerEncoder().apply(PARAMS),
                "hello".getBytes(StandardCharsets.UTF_8), negotiatedKey);
        // 3 字节签名：不是 AES 分组长度，解密阶段必炸
        wrapper.setSignature(Base64.getEncoder().encodeToString(new byte[]{1, 2, 3}));

        EncryptorException exception = Assertions.assertThrows(EncryptorException.class, () -> facade.decrypt(wrapper));
        // 具体原因仍要保留在 cause 里，便于服务端排查
        Assertions.assertTrue(exception.getCause() instanceof CryptoException,
                "cause should keep the original CryptoException, but was: " + exception.getCause());
    }

    @Test
    public void test_garbage_data_raises_encryptor_exception() {
        RSA rsa = new RSA();
        AES aes = new AES("CBC", "PKCS5Padding", KEY, IV);
        String negotiatedKey = rsa.encryptBase64(PARAMS, KeyType.PublicKey);

        EncryptorFacade facade = new EncryptorFacade(
                new EncryptorEncoder(new HtlASymmetricCryptoEncryptor(rsa), new Base64Encoder()),
                params -> new EncryptorEncoder(new HtlSymmetricCryptoEncryptor(aes), new Base64Encoder()),
                params -> new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()),
                        new HtlSymmetricCryptoEncryptor(aes)), new Base64Encoder()),
                Collections.emptyList());

        // key 本身不是合法的 RSA 密文（客户端乱填）
        EncryptorDataWrapper wrapper = new EncryptorDataWrapper("nonce", 1L, "sig", "not-a-valid-key", "data");
        Assertions.assertThrows(EncryptorException.class, () -> facade.decrypt(wrapper));
    }

    /**
     * 响应方向（encrypt(data,key)）必须复用请求方向已经协商出来的参数，不能再用 RSA 私钥解一次。
     * 一个加解密往返里的 RSA 私钥运算应只发生 1 次。
     */
    @Test
    public void test_response_encrypt_reuses_negotiated_params() {
        RSA rsa = new RSA();
        AES aes = new AES("CBC", "PKCS5Padding", KEY, IV);
        String negotiatedKey = rsa.encryptBase64(PARAMS, KeyType.PublicKey);

        final AtomicInteger negotiateDecryptCalls = new AtomicInteger();
        // 计数用的协商编码器：覆写 decrypt 记录调用次数后委托给真实 RSA
        EncryptorEncoder countingNegotiate = new EncryptorEncoder(
                new HtlASymmetricCryptoEncryptor(rsa), new Base64Encoder()) {
            @Override
            public byte[] decrypt(String data) {
                negotiateDecryptCalls.incrementAndGet();
                return super.decrypt(data);
            }
        };

        EncryptorFacade facade = new EncryptorFacade(
                countingNegotiate,
                params -> new EncryptorEncoder(new HtlSymmetricCryptoEncryptor(aes), new Base64Encoder()),
                params -> new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()),
                        new HtlSymmetricCryptoEncryptor(aes)), new Base64Encoder()),
                Collections.emptyList());

        EncryptorDataWrapper wrapper = EncryptorKit.encrypt(
                facade.getEncryptorEncoder().apply(PARAMS), facade.getSignerEncoder().apply(PARAMS),
                "hello".getBytes(StandardCharsets.UTF_8), negotiatedKey);
        // 请求方向：解出协商参数
        Assertions.assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), facade.decrypt(wrapper));
        // 响应方向：同一个 key，应命中记忆，不再 RSA
        facade.encrypt("world".getBytes(StandardCharsets.UTF_8), negotiatedKey);

        Assertions.assertEquals(1, negotiateDecryptCalls.get(),
                "the negotiated key must be decrypted (RSA) only once for a request/response round trip");
    }

    /**
     * 报文里的 key 来自未认证的客户端，记忆必须有界：容量到顶后整体清空，不能无限增长。
     */
    @Test
    public void test_negotiated_params_cache_is_bounded() {
        int capacity = 4;
        RSA rsa = new RSA();
        AES aes = new AES("CBC", "PKCS5Padding", KEY, IV);

        EncryptorFacade facade = new EncryptorFacade(
                new EncryptorEncoder(new HtlASymmetricCryptoEncryptor(rsa), new Base64Encoder()),
                params -> new EncryptorEncoder(new HtlSymmetricCryptoEncryptor(aes), new Base64Encoder()),
                params -> new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()),
                        new HtlSymmetricCryptoEncryptor(aes)), new Base64Encoder()),
                Collections.emptyList(),
                capacity);

        // 一个可解开的报文；签名不依赖 key，只替换 key 即可制造出互不相同的 RSA 密文
        EncryptorDataWrapper wrapper = EncryptorKit.encrypt(
                facade.getEncryptorEncoder().apply(PARAMS), facade.getSignerEncoder().apply(PARAMS),
                "hello".getBytes(StandardCharsets.UTF_8), rsa.encryptBase64(PARAMS, KeyType.PublicKey));

        for (int i = 0; i < capacity * 3; i++) {
            wrapper.setKey(rsa.encryptBase64(PARAMS, KeyType.PublicKey));
            facade.decrypt(wrapper);
            Assertions.assertTrue(facade.paramsCacheSize() <= capacity,
                    "params cache must never grow beyond its capacity, but was: " + facade.paramsCacheSize());
        }
    }
}
