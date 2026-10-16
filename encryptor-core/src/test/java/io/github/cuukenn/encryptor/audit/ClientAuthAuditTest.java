package io.github.cuukenn.encryptor.audit;

import cn.hutool.core.util.IdUtil;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.digest.MD5;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.core.EncoderStrategy;
import io.github.cuukenn.encryptor.core.EncryptorStrategy;
import io.github.cuukenn.encryptor.core.checker.InMemoryNonceChecker;
import io.github.cuukenn.encryptor.core.digester.HtlDigester;
import io.github.cuukenn.encryptor.core.encoder.Base64Encoder;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.core.encryptor.HtlASymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.encryptor.HtlSymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.signer.DigestWithEncryptSigner;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * 客户端身份 / 算法白名单的机制级审计：把 {@code docs/architecture/security-review.md} 里的
 * S1、S3 两条结论固化成可执行断言。
 * <p>
 * 这些用例断言的是<b>设计上的非目标</b>，不是 bug：
 * <ul>
 *   <li>S1：本机制<b>不提供客户端身份认证</b>。服务端公钥是公开的，任何人都能用它自造一份完全合法的报文，
 *       签名只保证"报文自洽"（nonce/timestamp/data 三者被同一把 AES key 覆盖），不保证"发起者是合法客户端"。</li>
 *   <li>S3：AES 的 mode/padding/key/iv 由客户端在报文里自带，服务端<b>没有算法白名单</b>，
 *       会按客户端给的组合现场构造加密器。</li>
 * </ul>
 * 写成可执行断言的目的，是防止将来有人误以为它提供认证、或误以为存在白名单，
 * 从而在此之上叠加"身份"相关的安全假设。修复/变更这些行为时，本用例会报警，请连同 security-review.md 一起更新。
 *
 * @author changgg
 */
public class ClientAuthAuditTest {
    /**
     * 攻击者只需服务端公钥即可发起攻击，这里把"没有任何私钥"写进方法签名，避免读者误以为用了服务端私钥。
     */
    private static final String ATTACKER_KEY = "0123456789abcdef";
    private static final String ATTACKER_IV = "abcdefghijklmnop";
    private static final String MODE = "CBC";
    private static final String PADDING = "PKCS5Padding";

    /**
     * 按 {@code EncryptorAutoConfiguration#encryptorFacadeFactory} 的方式装配服务端 facade：
     * 协商用 RSA 私钥解 key，业务加解密/签名用报文里自带的参数现场构造 AES。
     * 这里额外注册了示例应用同款的 nonce checker（{@code InMemoryNonceChecker}），
     * 以证明"过不了"的原因从来不是 nonce 复用。
     */
    private static EncryptorFacade serverFacade(RSA serverRsa) {
        EncoderStrategy encoder = new Base64Encoder();
        Function<String, EncryptorStrategy> strategyFunction = params -> {
            JSONObject obj = JSONUtil.parseObj(params);
            return new HtlSymmetricCryptoEncryptor(new AES(obj.getStr("mode"), obj.getStr("padding"),
                    encoder.decode(obj.getStr("key")),
                    Optional.ofNullable(obj.getStr("iv")).map(x -> x.getBytes(StandardCharsets.UTF_8)).orElse(null)));
        };
        return new EncryptorFacade(
                new EncryptorEncoder(new HtlASymmetricCryptoEncryptor(serverRsa), encoder),
                params -> new EncryptorEncoder(strategyFunction.apply(params), encoder),
                params -> new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()), strategyFunction.apply(params)), encoder),
                Collections.singletonList(new InMemoryNonceChecker(1000, Duration.ofSeconds(30))));
    }

    /**
     * 攻击方完整流程，<b>全程只用服务端公钥</b>（{@code serverPublicKey}），不接触任何私钥：
     * <ol>
     *   <li>自选 AES 的 mode/padding/key/iv，拼成参数 JSON；</li>
     *   <li>用服务端公钥 RSA 加密该 JSON，作为报文的 {@code key} 字段；</li>
     *   <li>用自己的 AES 加密业务明文，作为 {@code data} 字段；</li>
     *   <li>按 {@code nonce + timestamp + data} 拼串，用同一把 AES key 做 {@code AES_K(MD5)} 签名。</li>
     * </ol>
     */
    private static EncryptorDataWrapper forgeRequest(String serverPublicKey, String mode, String padding,
                                                     byte[] aesKey, String iv, byte[] plaintext) {
        // 1) 只用公钥构造 RSA：没有任何私钥参与
        RSA attackerRsa = new RSA(null, serverPublicKey);
        EncryptorEncoder negotiate = new EncryptorEncoder(new HtlASymmetricCryptoEncryptor(attackerRsa), new Base64Encoder());
        Map<String, Object> keyParams = new LinkedHashMap<>();
        keyParams.put("key", Base64.getEncoder().encodeToString(aesKey));
        keyParams.put("mode", mode);
        keyParams.put("padding", padding);
        // ECB 不使用 IV（BouncyCastle 会直接抛 "ECB mode does not use an IV"），因此 iv 为 null 时不放进参数 JSON
        if (iv != null) {
            keyParams.put("iv", iv);
        }
        String keyField = negotiate.encrypt(JSONUtil.toJsonStr(keyParams).getBytes(StandardCharsets.UTF_8));

        // 2) 用自己的 AES 加密业务数据
        byte[] ivBytes = iv == null ? null : iv.getBytes(StandardCharsets.UTF_8);
        AES aes = new AES(mode, padding, aesKey, ivBytes);
        EncryptorEncoder dataEncryptor = new EncryptorEncoder(new HtlSymmetricCryptoEncryptor(aes), new Base64Encoder());
        String data = dataEncryptor.encrypt(plaintext);

        // 3) 用同一把 AES key 伪装签名：客户端自己签、服务端照验
        SignerEncoder signer = new SignerEncoder(
                new DigestWithEncryptSigner(new HtlDigester(new MD5()), new HtlSymmetricCryptoEncryptor(aes)),
                new Base64Encoder());
        String nonce = IdUtil.fastSimpleUUID();
        long timestamp = System.currentTimeMillis();
        String signature = signer.sign((nonce + timestamp + data).getBytes(StandardCharsets.UTF_8));

        return new EncryptorDataWrapper(nonce, timestamp, signature, keyField, data);
    }

    /**
     * S1：签名只保证"报文自洽"，不提供客户端身份认证 ——
     * 攻击者<b>不需要任何私钥</b>，只要拿到服务端公钥，就能自造一份能通过验签、能被成功解密的合法请求。
     * <p>
     * 这不是 bug，而是"公钥是公开的、签名密钥来自客户端自选的 AES key（在 key 字段里用公钥加密后一起传上来）"
     * 这一设计的直接后果。任何"以为服务端能识别调用方身份"的假设都不成立。
     */
    @Test
    public void test_anyone_with_the_public_key_can_forge_a_valid_request() {
        RSA serverRsa = new RSA();
        EncryptorFacade server = serverFacade(serverRsa);

        // 攻击者掌握的全部信息：服务端公钥（公开信息）
        String serverPublicKey = serverRsa.getPublicKeyBase64();
        byte[] attackerKey = ATTACKER_KEY.getBytes(StandardCharsets.UTF_8);
        byte[] forgedPlaintext = "transfer=1000000&to=attacker".getBytes(StandardCharsets.UTF_8);

        EncryptorDataWrapper forged = forgeRequest(serverPublicKey, MODE, PADDING, attackerKey, ATTACKER_IV, forgedPlaintext);

        // 服务端既不拒绝、也不报警：成功解出攻击者的明文
        Assertions.assertArrayEquals(forgedPlaintext, server.decrypt(forged));
    }

    /**
     * S3：客户端可自选 AES 算法/参数，服务端没有白名单 ——
     * 参数 JSON 里的 mode/padding/key/iv 全由客户端决定，服务端会按这些值现场 {@code new AES(...)}，
     * 即使用上服务端默认组合之外的 {@code ECB}、以及服务端默认不会用的 24 字节密钥，也照样接受并解密成功。
     * <p>
     * 当前行为 = 无白名单。这不是断言它是"安全"的，而是钉住现状，防止将来误以为有白名单。
     */
    @Test
    public void test_server_accepts_any_client_chosen_algorithm_without_whitelist() {
        RSA serverRsa = new RSA();
        EncryptorFacade server = serverFacade(serverRsa);

        String serverPublicKey = serverRsa.getPublicKeyBase64();
        // 服务端示例默认跑 CBC/PKCS5Padding + 16 字节 key，这里故意换成 ECB + 24 字节 key
        byte[] attackerKey = "0123456789abcdefghijklmn".getBytes(StandardCharsets.UTF_8);
        Assertions.assertEquals(24, attackerKey.length);
        byte[] forgedPlaintext = "algorithm=ECB&keyLen=24".getBytes(StandardCharsets.UTF_8);

        EncryptorDataWrapper forged = forgeRequest(serverPublicKey, "ECB", PADDING, attackerKey, null, forgedPlaintext);

        // 服务端没有任何 mode/padding/keyLength 白名单校验：照单全收并解密成功
        Assertions.assertArrayEquals(forgedPlaintext, server.decrypt(forged));
    }
}
