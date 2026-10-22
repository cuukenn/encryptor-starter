package io.github.cuukenn.encryptor.example.boot3;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.Direction;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * reactive <b>共享</b>线（encryptor-spring-boot-starter-reactive 1.0.0）的行为对等
 * （Task 2 裁定共享：装配语义 + 协议栈在 Spring 6 / JDK 17 上无行为差分——以,
 * 复制后的测试常驻 boot3-example 证明该判定在发布形态下成立）。
 *
 * <p>把 javax 线 GatewayJweTest 的构建/断言口径原样搬到 Boot 3.5（Spring 6.2、micrometer 1.15、
 * reactor 3.7 类路径）上执行：nimbuseal → protocol.openRequest → codec().encryptResponse →
 * 客户端 dir 解密。若无行为差分、协议栈没被 Spring 版本差异影响，全部断言照常绿。</p>
 *
 * @author changgg
 */
class Boot3ReactiveBehaviorParityTest {
    private static final String KID = "k1";

    private static KeyPair staticPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void 共享reactiveJar在Boot3装配与协议行为对等() {
        KeyPair pair = staticPair();
        String privateKey = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
        String publicKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                io.github.cuukenn.encryptor.reactive.configuration.EncryptorReactiveAutoConfiguration.class))
            .withPropertyValues(
                "encryptor.config.reactive.keys[0].kid=" + KID,
                "encryptor.config.reactive.keys[0].type=RSA",
                "encryptor.config.reactive.keys[0].private-key=" + privateKey,
                "encryptor.config.reactive.keys[0].public-key=" + publicKey,
                "encryptor.config.reactive.ttl=5m",
                "encryptor.config.reactive.failure-status=400",
                "encryptor.config.reactive.max-request-size=2048",
                "encryptor.config.reactive.nonce-retention=10m")
            .run(context -> {
                // 装配语义：protocol / runtime / 配置绑定全在
                assertThat(context.containsBean("defaultProtocol")).isTrue();
                assertThat(context.getBean(EncryptorRuntime.class)).isNotNull();
                io.github.cuukenn.encryptor.reactive.config.EncryptorConfig config = context.getBean(
                    io.github.cuukenn.encryptor.reactive.config.EncryptorConfig.class);
                assertThat(config.getMaxRequestSize()).isEqualTo(2048L);
                assertThat(config.getTtl()).isEqualTo(Duration.ofMinutes(5));
                assertThat(config.getNonceRetention()).isEqualTo(Duration.ofMinutes(10));
                assertThat(config.getFailureStatus()).isEqualTo(400);
                // 协议行为对等：同样的 nimbus 封送 → 解开 plaintext → 同一 CEK 回封 → dir 解回
                DefaultProtocol protocol = context.getBean(DefaultProtocol.class);
                String plaintext = "{\"parity\":\"boot3\"}";
                String compact = sealNimbus(plaintext, "/api/a", "POST", (RSAPublicKey) pair.getPublic());
                io.github.cuukenn.encryptor.jose.JweContext ctx = protocol.openRequest(compact, "/api/a", "POST");
                assertThat(ctx.plaintext()).isEqualTo(plaintext.getBytes(StandardCharsets.UTF_8));
                String jwe = protocol.codec().encryptResponse(
                    "{\"downstream\":1}".getBytes(StandardCharsets.UTF_8),
                    ctx.cek(), ctx.enc(), "/api/a", "POST",
                    System.currentTimeMillis(), UUID.randomUUID().toString());
                byte[] decoded = decryptResponseDer(jwe, ctx.cek());
                assertThat(new String(decoded, StandardCharsets.UTF_8)).isEqualTo("{\"downstream\":1}");
                // 拒绝面对等：重放同一报文必须被防重放拒绝（REPLAY 分类，仍是 EncryptorException）
                try {
                    protocol.openRequest(compact, "/api/a", "POST");
                    throw new AssertionError("重放未拒绝");
                } catch (EncryptorException expected) {
                    assertThat(expected.failure()).isEqualTo(EncryptorFailure.REPLAY);
                }
                // cipher 上下文清零语义也保持
                ctx.destroy();
                assertThat(ctx.cek()).containsOnly((byte) 0);
            });
    }

    // ---- 与 javax 线 GatewayJweTest 共用的客户端口径（直接可对比，不做任何适配） ----

    private static String sealNimbus(String plaintext, String uri, String method, RSAPublicKey publicKey) throws Exception {
        long ts = System.currentTimeMillis();
        String nonce = UUID.randomUUID().toString();
        Map<String, Object> claims = ContextAad.claims(uri, method, Direction.REQUEST, ts, nonce);
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
            .keyID(KID).customParams(claims).build();
        JWEObject jwe = new JWEObject(header, new Payload(plaintext));
        jwe.encrypt(new RSAEncrypter(publicKey));
        return jwe.serialize();
    }

    /** alg=dir 响应手工解（AAD = protected header ASCII），同 GatewayJweTest.decryptResponse。 */
    private static byte[] decryptResponseDer(String compact, byte[] cek) throws Exception {
        String[] parts = compact.split("\\.");
        byte[] iv = Base64.getUrlDecoder().decode(parts[2]);
        byte[] ciphertext = Base64.getUrlDecoder().decode(parts[3]);
        byte[] tag = Base64.getUrlDecoder().decode(parts[4]);
        byte[] ctAndTag = Arrays.copyOf(ciphertext, ciphertext.length + tag.length);
        System.arraycopy(tag, 0, ctAndTag, ciphertext.length, tag.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
        cipher.updateAAD(parts[0].getBytes(StandardCharsets.US_ASCII));
        return cipher.doFinal(ctAndTag);
    }
}
