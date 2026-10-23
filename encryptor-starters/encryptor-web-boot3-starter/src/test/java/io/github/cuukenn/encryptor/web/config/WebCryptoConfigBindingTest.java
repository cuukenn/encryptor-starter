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
            .withPropertyValues("encryptor.config.web.crypto-config.[^/api/.*]=k1")
            .run(context -> {
                assertThat(context).hasNotFailed();
                WebEncryptorConfig web = context.getBean(WebEncryptorConfig.class);
                // 不用 [key] 写法时 Spring Boot 会把 ^/api/.* 静默改成 api（已知坑 P3-7）；[key] 写法必须原样保住
                assertThat(web.getCryptoConfig()).containsOnlyKeys("^/api/.*");
                assertThat(web.getCryptoConfig().get("^/api/.*")).containsExactly("k1");
            });
    }

    @Test
    void cryptoConfig引用未知kid时启动失败() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .withPropertyValues("encryptor.config.web.crypto-config.[/api/.*]=missing-kid")
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure()).hasStackTraceContaining("missing-kid");
            });
    }

    @Test
    void cryptoConfig保持声明顺序() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .withPropertyValues("encryptor.config.web.crypto-config.[/pay/.*]=k1",
                "encryptor.config.web.crypto-config.[/pay/.+]=k1")
            .run(context -> {
                assertThat(context).hasNotFailed();
                WebEncryptorConfig web = context.getBean(WebEncryptorConfig.class);
                assertThat(web.getCryptoConfig().keySet()).containsExactly("/pay/.*", "/pay/.+");
            });
    }

    @Test
    void 过滤器顺序非法时启动失败() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .withPropertyValues("encryptor.config.web.filter-config.encryptor-res-filter-order=-13")
            .run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure()).hasStackTraceContaining("filter-config");
            });
    }

    @Test
    void 默认值符合设计() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .run(context -> {
                assertThat(context).hasNotFailed();
                WebEncryptorConfig web = context.getBean(WebEncryptorConfig.class);
                assertThat(web.isEnable()).isTrue();
                // SSE 默认跳过：默认全缓冲会让事件在 4MiB 之前一个都发不出去
                assertThat(web.getSkipResContentType()).contains("text/event-stream");
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

    @Test
    void 旧名black名单仍可绑定并落到skip名单() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .withPropertyValues("encryptor.config.web.black-uris[0]=/api/open.*",
                "encryptor.config.web.black-methods[0]=OPTIONS",
                "encryptor.config.web.black-req-content-type[0]=multipart/form-data",
                "encryptor.config.web.black-res-content-type[0]=text/event-stream")
            .run(context -> {
                assertThat(context).hasNotFailed();
                WebEncryptorConfig web = context.getBean(WebEncryptorConfig.class);
                // P3-4：旧名只是 alias，写进的就是同一份生效名单（getter 也保留）
                assertThat(web.getSkipUris()).containsExactly("/api/open.*");
                assertThat(web.getSkipMethods()).containsExactly("OPTIONS");
                assertThat(web.getSkipReqContentType()).containsExactly("multipart/form-data");
                assertThat(web.getSkipResContentType()).containsExactly("text/event-stream");
                assertThat(web.getBlackUris()).containsExactly("/api/open.*");
            });
    }

    @Test
    void 新旧名字可共存并合并去重() {
        runner.withPropertyValues(rsaKeyProps("k1"))
            .withPropertyValues("encryptor.config.web.skip-uris[0]=/api/open.*",
                "encryptor.config.web.black-uris[0]=/api/open.*",
                "encryptor.config.web.black-uris[1]=/other")
            .run(context -> {
                assertThat(context).hasNotFailed();
                WebEncryptorConfig web = context.getBean(WebEncryptorConfig.class);
                // 两个 setter 都是「合并 + 按值去重」，与绑定顺序无关
                assertThat(web.getSkipUris()).containsExactly("/api/open.*", "/other");
            });
    }
}
