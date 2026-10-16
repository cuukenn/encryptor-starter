package io.github.cuukenn.encryptor.audit;

import cn.hutool.crypto.CryptoException;
import cn.hutool.crypto.digest.MD5;
import cn.hutool.crypto.symmetric.AES;
import io.github.cuukenn.encryptor.core.EncryptorStrategy;
import io.github.cuukenn.encryptor.core.digester.HtlDigester;
import io.github.cuukenn.encryptor.core.encoder.Base64Encoder;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.core.encryptor.GroupEncryptor;
import io.github.cuukenn.encryptor.core.encryptor.HtlSymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.signer.DigestWithEncryptSigner;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.kit.EncryptorKit;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * 机制合理性审计：把"加解密逻辑本身"的行为用可执行断言固定下来，
 * 每一条都对应 docs/architecture/security-review.md 里的一个结论。
 * <p>
 * 注意：这些用例断言的是**当前**行为（其中数条是缺陷），它们的作用是让结论可复现、可回归，
 * 而不是声明这些行为是"正确"的。修复对应缺陷时，把断言改成期望行为即可（先红后绿）。
 *
 * @author changgg
 */
public class CryptoMechanismAuditTest {
    /**
     * 前端 aes.generateBase64Key(128) 会把 16 个字符 Base64 化后作为 key 传给服务端，
     * servlet 侧 Base64 解码回 16 字节，所以这里直接用 16 字节密钥。
     */
    private static final byte[] KEY = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8);
    private static final String MODE = "CBC";
    private static final String PADDING = "PKCS5Padding";
    private static final int BLOCK_SIZE = 16;
    private static final int GROUP_SIZE = 4;

    private static EncryptorEncoder encryptorEncoder() {
        return new EncryptorEncoder(new HtlSymmetricCryptoEncryptor(new AES(MODE, PADDING, KEY, IV)), new Base64Encoder());
    }

    private static SignerEncoder signerEncoder() {
        return new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()),
                new HtlSymmetricCryptoEncryptor(new AES(MODE, PADDING, KEY, IV))), new Base64Encoder());
    }

    /**
     * S7：签名输入是 nonce + timestamp + data 的裸拼接，没有分隔符/长度前缀。
     * 攻击者可控的两段（nonce、timestamp）在边界处可任意挪动字符，而拼接结果不变 —— 同一份签名对多组
     * (nonce, timestamp) 都成立。因此"nonce 唯一性"不能靠签名保证，只能靠 checker（且 checker 默认未注册）。
     */
    @Test
    public void test_signature_input_is_ambiguous_across_nonce_and_timestamp() {
        EncryptorEncoder encryptor = encryptorEncoder();
        SignerEncoder signer = signerEncoder();
        String cipher = encryptor.encrypt("balance=100".getBytes(StandardCharsets.UTF_8));

        String nonce = "8f3c1d2e-4a5b-6c7d-8e9f-000000000001";
        long timestamp = 1750000000000L;
        // 把 timestamp 的首位挪到 nonce 末尾：两个字段都变了，拼接结果一字不差
        String otherNonce = nonce + "1";
        long otherTimestamp = 750000000000L;
        Assertions.assertEquals(nonce + timestamp + cipher, otherNonce + otherTimestamp + cipher);

        String signature = signer.sign((nonce + timestamp + cipher).getBytes(StandardCharsets.UTF_8));
        EncryptorDataWrapper forged = new EncryptorDataWrapper(otherNonce, otherTimestamp, signature, "key", cipher);

        // 同一份密文、同一份签名，换一组 (nonce, timestamp) 照样验签通过
        Assertions.assertArrayEquals("balance=100".getBytes(StandardCharsets.UTF_8),
                EncryptorKit.decrypt(encryptor, signer, forged));
    }

    /**
     * S14：协议里 IV 由客户端提供且没有新鲜度校验，CBC + 固定 IV 就是确定性加密。
     * 攻击者可据此判断"两次请求的明文是否相同/前缀是否相同"。
     */
    @Test
    public void test_reused_key_and_iv_make_ciphertext_deterministic() {
        EncryptorEncoder encryptor = encryptorEncoder();
        byte[] plaintext = "same-plaintext".getBytes(StandardCharsets.UTF_8);
        Assertions.assertEquals(encryptor.encrypt(plaintext), encryptor.encrypt(plaintext));

        // 明文首个分组相同 -> 密文首个分组相同
        EncryptorStrategy raw = new HtlSymmetricCryptoEncryptor(new AES(MODE, PADDING, KEY, IV));
        byte[] first = raw.encrypt("AAAAAAAAAAAAAAAA-BBB".getBytes(StandardCharsets.UTF_8));
        byte[] second = raw.encrypt("AAAAAAAAAAAAAAAA-CCC".getBytes(StandardCharsets.UTF_8));
        Assertions.assertArrayEquals(Arrays.copyOf(first, BLOCK_SIZE), Arrays.copyOf(second, BLOCK_SIZE));
    }

    /**
     * 机制的核心承诺（报文自洽性）是成立的：只改密文、不动签名，会被验签拦下并给出明确原因。
     */
    @Test
    public void test_tampered_payload_is_caught_by_signature_check() {
        EncryptorEncoder encryptor = encryptorEncoder();
        SignerEncoder signer = signerEncoder();
        EncryptorDataWrapper wrapper = EncryptorKit.encrypt(encryptor, signer, "balance=100".getBytes(StandardCharsets.UTF_8), "key");

        wrapper.setData(encryptor.encrypt("balance=999".getBytes(StandardCharsets.UTF_8)));
        EncryptorException exception = Assertions.assertThrows(EncryptorException.class,
                () -> EncryptorKit.decrypt(encryptor, signer, wrapper));
        Assertions.assertEquals("sig check error", exception.getMessage());
    }

    /**
     * S15/P1-12：但"篡改 signature 字段本身"走的是另一条路 —— 先拿 AES 解签名，
     * 于是抛的是 hutool 的 CryptoException（IllegalBlockSizeException），而不是 "sig check error"。
     * 失败模式因此可区分，且"有人在改报文"这个信号在日志里消失了。
     */
    @Test
    public void test_malformed_signature_escapes_as_crypto_exception() {
        EncryptorEncoder encryptor = encryptorEncoder();
        SignerEncoder signer = signerEncoder();
        EncryptorDataWrapper wrapper = EncryptorKit.encrypt(encryptor, signer, "x".getBytes(StandardCharsets.UTF_8), "key");

        // 3 字节，不是分组长度整数倍
        wrapper.setSignature("AAAA");
        Assertions.assertThrows(CryptoException.class, () -> EncryptorKit.decrypt(encryptor, signer, wrapper));
    }

    /**
     * P2-8（2026-10-16 已修）：GroupEncryptor 现在只按 groupSize 切**编码后的密文**（传输分片），
     * 整段明文只加密一次 —— 重复的明文块不再产生重复的密文分片，明文结构不再泄漏（往返仍成立）。
     * <p>
     * 变更前本用例断言的是"泄漏存在"（两个分片相等）；修复对应缺陷后断言翻转为"不再泄漏"。
     */
    @Test
    public void test_group_encryptor_does_not_leak_repeated_plaintext_blocks() {
        GroupEncryptor groupEncryptor = new GroupEncryptor(encryptorEncoder(), GROUP_SIZE);
        byte[] plaintext = "abcdabcd".getBytes(StandardCharsets.UTF_8);
        String cipher = groupEncryptor.encrypt(plaintext);

        String[] groups = cipher.split("\\.");
        Assertions.assertTrue(groups.length > 1);
        // 重复明文块 -> 密文分片互不相同：CBC 的链式作用没有被分片打断
        Assertions.assertNotEquals(groups[0], groups[1]);
        // 加密粒度是整段明文：去掉分隔符拼回分片 == 一次性加密整段（分片只影响传输）
        Assertions.assertEquals(encryptorEncoder().encrypt(plaintext), String.join("", groups));
        Assertions.assertArrayEquals(plaintext, groupEncryptor.decrypt(cipher));
    }
}
