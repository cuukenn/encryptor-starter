package io.github.cuukenn.encryptor.web.config;

import io.github.cuukenn.encryptor.configuration.EncryptorAutoConfiguration;
import io.github.cuukenn.encryptor.web.configuration.WebEncryptorConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * web 配置绑定：crypto-config 的 [key] 括号语法必须保住含 {@code .} 的正则 uri key（Ruling 8b-R5 的回归钉）。
 *
 * @author changgg
 */
class WebCryptoConfigBindingTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(EncryptorAutoConfiguration.class, WebEncryptorConfiguration.class));

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

    @Test
    void 括号key绑定含点的正则uri() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .withPropertyValues("encryptor.config.web.crypto-config.[^/api/.*]=k1,k2")
            .run(context -> {
                assertThat(context).hasNotFailed();
                WebEncryptorConfig web = context.getBean(WebEncryptorConfig.class);
                // 不用 [key] 写法时 Spring Boot 会把 ^/api/.* 静默改成 api（已知坑 P3-7）；[key] 写法必须原样保住
                assertThat(web.getCryptoConfig()).containsOnlyKeys("^/api/.*");
                assertThat(web.getCryptoConfig().get("^/api/.*")).containsExactly("k1", "k2");
            });
    }

    @Test
    void 默认值符合设计() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .run(context -> {
                assertThat(context).hasNotFailed();
                WebEncryptorConfig web = context.getBean(WebEncryptorConfig.class);
                assertThat(web.isEnable()).isTrue();
                assertThat(web.getFilterConfig()).isNotNull();
                // 生产链序：web(-12 决策+解密) → params(-11) → body(-10) → response(-3 包住业务)
                assertThat(web.getFilterConfig().getEncryptorFilterOrder()).isEqualTo(-12);
                assertThat(web.getFilterConfig().getEncryptorReqParamsFilterOrder()).isEqualTo(-11);
                assertThat(web.getFilterConfig().getEncryptorReqBodyFilterOrder()).isEqualTo(-10);
                assertThat(web.getFilterConfig().getEncryptorResFilterOrder()).isEqualTo(-3);
                // 4 个过滤器全部注册
                assertThat(context).hasBean("defaultRequestParameterEncryptorFilter");
                assertThat(context).hasBean("defaultRequestBodyEncryptorFilter");
                assertThat(context).hasBean("defaultResponseEncryptorFilter");
                assertThat(context).hasBean("defaultWebEncryptorFilter");
            });
    }
}
