package io.github.cuukenn.encryptor.config;

import io.github.cuukenn.encryptor.configuration.EncryptorAutoConfiguration;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * v2 配置形态绑定 + 自动装配装配出 {@link DefaultProtocol} 的回归测试。
 *
 * @author changgg
 */
class EncryptorConfigBindingTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(EncryptorAutoConfiguration.class));

    private static String[] rsaKeyProps(String kid) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            String priv = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
            String pub = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
            return new String[]{
                "encryptor.config.keys[0].kid=" + kid,
                "encryptor.config.keys[0].private-key=" + priv,
                "encryptor.config.keys[0].public-key=" + pub,
            };
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String[] sm2KeyProps(String kid) {
        try {
            X9ECParameters domain = CustomNamedCurves.getByName("sm2p256v1");
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.init(new ECKeyGenerationParameters(new ECDomainParameters(domain), new SecureRandom()));
            AsymmetricCipherKeyPair pair = generator.generateKeyPair();
            ECPrivateKeyParameters priv = (ECPrivateKeyParameters) pair.getPrivate();
            ECPublicKeyParameters pub = (ECPublicKeyParameters) pair.getPublic();
            String privB64 = Base64.getEncoder()
                .encodeToString(PrivateKeyInfoFactory.createPrivateKeyInfo(priv).getEncoded(ASN1Encoding.DER));
            String pubB64 = Base64.getEncoder()
                .encodeToString(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub).getEncoded(ASN1Encoding.DER));
            return new String[]{
                "encryptor.config.keys[0].kid=" + kid,
                "encryptor.config.keys[0].type=SM2",
                "encryptor.config.keys[0].private-key=" + privB64,
                "encryptor.config.keys[0].public-key=" + pubB64,
            };
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void 密钥绑定后产出DefaultProtocol且v1工厂bean仍在() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .run(context -> {
                assertThat(context).hasSingleBean(DefaultProtocol.class);
                assertThat(context).hasSingleBean(EncryptorRuntime.class);
                DefaultProtocol protocol = context.getBean(DefaultProtocol.class);
                assertThat(protocol.keys().activeKid()).isEqualTo("k1");
                assertThat(protocol.allowedAlgs()).containsExactly("RSA-OAEP-256");
            });
    }

    @Test
    void allowedAlgs覆盖默认白名单() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .withPropertyValues("encryptor.config.allowed-algs=SM2")
            .run(context -> {
                DefaultProtocol protocol = context.getBean(DefaultProtocol.class);
                assertThat(protocol.allowedAlgs()).containsExactly("SM2");
            });
    }

    @Test
    void ttl绑定毫秒数() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .withPropertyValues("encryptor.config.ttl=2m")
            .run(context -> {
                DefaultProtocol protocol = context.getBean(DefaultProtocol.class);
                assertThat(protocol.ttlMillis()).isEqualTo(2 * 60 * 1000L);
            });
    }

    @Test
    void 默认值符合设计文档() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .run(context -> {
                EncryptorConfig config = context.getBean(EncryptorConfig.class);
                assertThat(config.isRequireEncrypted()).isTrue();
                assertThat(config.getFailureStatus()).isEqualTo(400);
                assertThat(config.getMaxRequestSize()).isEqualTo(1048576L);
                assertThat(config.getMaxResponseSize()).isEqualTo(4194304L);
                assertThat(config.getDiscovery().isEnable()).isTrue();
                assertThat(config.getDiscovery().getPath()).isEqualTo("/.well-known/encryptor-keys");
                assertThat(config.getBypass().isRequest()).isFalse();
                assertThat(config.getBypass().isResponse()).isFalse();
            });
    }

    @Test
    void 没有密钥时启动失败() {
        runner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(rootCause(context.getStartupFailure())).hasMessageContaining("没有配置任何密钥");
        });
    }

    @Test
    void activeKid不存在时启动失败() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .withPropertyValues("encryptor.config.active-kid=nope")
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(rootCause(context.getStartupFailure())).hasMessageContaining("active-kid 不存在");
            });
    }

    private static Throwable rootCause(Throwable t) {
        Throwable current = t;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    @Test
    void SM2密钥类型绑定并进入默认白名单() {
        runner.withPropertyValues(sm2KeyProps("sm2-1"))
            .run(context -> {
                DefaultProtocol protocol = context.getBean(DefaultProtocol.class);
                assertThat(protocol.allowedAlgs()).containsExactly("SM2");
            });
    }

    @Test
    void bypass初始值进入Runtime() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .withPropertyValues("encryptor.config.bypass.request=true")
            .run(context -> {
                EncryptorRuntime runtime = context.getBean(EncryptorRuntime.class);
                assertThat(runtime.bypassRequest()).isTrue();
                assertThat(runtime.bypassResponse()).isFalse();
            });
    }

    @Test
    void 启动摘要包含kid与公钥指纹() {
        ch.qos.logback.classic.Logger log =
            (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(EncryptorAutoConfiguration.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
            new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        log.addAppender(appender);
        try {
            runner.withPropertyValues(rsaKeyProps("k-fp")).run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(appender.list).isNotEmpty();
                assertThat(appender.list).anySatisfy(event -> {
                    assertThat(event.getFormattedMessage()).contains("k-fp").contains("fp=");
                });
            });
        } finally {
            log.detachAppender(appender);
        }
    }
}
