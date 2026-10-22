package io.github.cuukenn.encryptor.example.boot3;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.Direction;
import io.github.cuukenn.encryptor.micrometer.MicrometerEncryptorListener;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.reactive.configuration.EncryptorReactiveAutoConfiguration;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 微观装配次序验证（micrometer <b>共享</b>线 1.0.0，Boot 3.5）。
 *
 * <p>正面证据在真实 Boot 应用（{@code Boot3GatewayEndToEndTest#装配面冒烟与micrometer计数递增}：
 * 完整 auto-configuration 排序中 listener 装配成功 + 真实协议调用计数递增）；本 runner 组
 * 验证两处包级语义（与 Task 2 验证口径一致）：</p>
 * <ol>
 *   <li>注册表在场（与装配评估同相）时的完整计数器注册面（枚举全量失败分类）；</li>
 *   <li>零注册表时整块静默不装配（与 javax 线文档语义一致，勿改）。</li>
 * </ol>
 * <p>跟进项（保持观测）：共享 jar 的 {@code @AutoConfigureAfter} 只声明 MetricsAutoConfiguration，
 * 与 SimpleMetricsExportAutoConfiguration 之间无排序约束——全量 imports 下排序对，
 * 本示例上下文即其实证。</p>
 *
 * @author changgg
 */
class Boot3MicrometerAutoConfigureAfterTest {
    private static final String KID = "k1";

    private static KeyPair newPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 注册表在场（用户相位先行注册，等价于生产里 actuator 先于自动装配提供注册表）时的装配面。 */
    @Test
    void 注册表在场时监听器接线且失败分类计数器注册齐() {
        KeyPair pair = newPair();
        String privateKey = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
        String publicKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        new ApplicationContextRunner()
            .withBean("simpleMeterRegistry", SimpleMeterRegistry.class)
            .withConfiguration(AutoConfigurations.of(
                EncryptorReactiveAutoConfiguration.class,
                io.github.cuukenn.encryptor.micrometer.EncryptorMicrometerAutoConfiguration.class))
            .withPropertyValues(
                "encryptor.config.reactive.keys[0].kid=" + KID,
                "encryptor.config.reactive.keys[0].type=RSA",
                "encryptor.config.reactive.keys[0].private-key=" + privateKey,
                "encryptor.config.reactive.keys[0].public-key=" + publicKey)
            .run(context -> {
                assertThat(context.getBean("micrometerEncryptorListener")).isInstanceOf(MicrometerEncryptorListener.class);
                MeterRegistry registry = context.getBean(MeterRegistry.class);
                // 失败分类计数器构造期注册（枚举全量、两侧都要有）——这正是 @AutoConfigureAfter
                // 保证"注册表先于本装配评估"要换来的能力
                for (EncryptorFailure failure : EncryptorFailure.values()) {
                    assertThat(registry.find("encryptor.decrypt.failures").tag("failure", failure.name()).counter())
                        .as("decrypt.failures[%s]", failure.name()).isNotNull();
                    assertThat(registry.find("encryptor.encrypt.failures").tag("failure", failure.name()).counter())
                        .as("encrypt.failures[%s]", failure.name()).isNotNull();
                }
                // 监听器真实接线：协议栈组合了它，一次真实 openRequest 后成功计数递增
                DefaultProtocol protocol = context.getBean(DefaultProtocol.class);
                double before = countOf(registry, "encryptor.decrypt", "result", "success");
                protocol.openRequest(sealNimbus("{\"metric\":1}", "/api/a", "POST",
                    (RSAPublicKey) pair.getPublic()), "/api/a", "POST");
                assertThat(countOf(registry, "encryptor.decrypt", "result", "success")).isGreaterThan(before);
            });
    }

    /** 负控制：没有注册表时整块静默不装配（与 javax 线文档语义一致）。 */
    @Test
    void 无MeterRegistry时静默不装配与javax线一致() {
        KeyPair pair = newPair();
        String privateKey = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
        String publicKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                EncryptorReactiveAutoConfiguration.class,
                io.github.cuukenn.encryptor.micrometer.EncryptorMicrometerAutoConfiguration.class))
            .withPropertyValues(
                "encryptor.config.reactive.keys[0].kid=" + KID,
                "encryptor.config.reactive.keys[0].type=RSA",
                "encryptor.config.reactive.keys[0].private-key=" + privateKey,
                "encryptor.config.reactive.keys[0].public-key=" + publicKey)
            .run(context -> assertThat(context.containsBean("micrometerEncryptorListener")).isFalse());
    }

    private static double countOf(MeterRegistry registry, String name, String tagKey, String tagValue) {
        Counter counter = registry.find(name).tag(tagKey, tagValue).counter();
        return counter == null ? 0 : counter.count();
    }

    /** nimbus 封送（与 javax 线 GatewayJweTest.seal 完全同一口径）。 */
    private static String sealNimbus(String plaintext, String uri, String method, RSAPublicKey publicKey) {
        try {
            long ts = System.currentTimeMillis();
            String nonce = UUID.randomUUID().toString();
            Map<String, Object> claims = ContextAad.claims(uri, method, Direction.REQUEST, ts, nonce);
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID(KID).customParams(claims).build();
            JWEObject jwe = new JWEObject(header, new Payload(plaintext));
            jwe.encrypt(new RSAEncrypter(publicKey));
            return jwe.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
