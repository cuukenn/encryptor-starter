package io.github.cuukenn.encryptor.reactive.gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 网关侧 P3-4（与 servlet 侧 {@code WebCryptoConfigBindingTest} 成对）：旧名 {@code black-*}
 * 作为 alias 仍可绑定，绑定完成后由 {@code afterPropertiesSet()} 并入 {@code skip-*} 生效名单；
 * 新旧名字共存时合并去重。
 *
 * <p>这里用 {@link Binder} 直接绑定属性名（不走 Spring 上下文），因为要钉的正是「属性名 → 绑定」这一层：
 * 名字改了但旧配置不能失效。也正因为不走容器，{@code afterPropertiesSet()} 需要显式调用
 * ——上下文里由容器在绑定后调用。</p>
 *
 * @author changgg
 */
class GatewaySkipAliasBindingTest {

    private static GatewayEncryptorConfig bind(Map<String, Object> props) throws Exception {
        GatewayEncryptorConfig config = new Binder(new MapConfigurationPropertySource(props))
            .bind(GatewayEncryptorConfig.PREFIX, Bindable.of(GatewayEncryptorConfig.class))
            .orElseGet(GatewayEncryptorConfig::new);
        config.afterPropertiesSet();
        return config;
    }

    @Test
    @SuppressWarnings("deprecation")
    void 旧名black名单仍可绑定并落到skip名单() throws Exception {
        Map<String, Object> props = new HashMap<>();
        props.put(GatewayEncryptorConfig.PREFIX + ".black-uris[0]", "/api/open.*");
        props.put(GatewayEncryptorConfig.PREFIX + ".black-methods[0]", "OPTIONS");
        props.put(GatewayEncryptorConfig.PREFIX + ".black-req-content-type[0]", "multipart/form-data");
        props.put(GatewayEncryptorConfig.PREFIX + ".black-res-content-type[0]", "text/event-stream");
        GatewayEncryptorConfig config = bind(props);
        assertThat(config.getSkipUris()).containsExactly("/api/open.*");
        assertThat(config.getSkipMethods()).containsExactly("OPTIONS");
        assertThat(config.getSkipReqContentType()).containsExactly("multipart/form-data");
        assertThat(config.getSkipResContentType()).containsExactly("text/event-stream");
        // 旧 getter 读到的还是旧名那一份（未合并），只是不再推荐使用
        assertThat(config.getBlackUris()).containsExactly("/api/open.*");
    }

    @Test
    void 新名skip名单可绑定() throws Exception {
        Map<String, Object> props = new HashMap<>();
        props.put(GatewayEncryptorConfig.PREFIX + ".skip-uris[0]", "/api/open.*");
        props.put(GatewayEncryptorConfig.PREFIX + ".skip-methods[0]", "OPTIONS");
        props.put(GatewayEncryptorConfig.PREFIX + ".skip-req-content-type[0]", "multipart/form-data");
        props.put(GatewayEncryptorConfig.PREFIX + ".skip-res-content-type[0]", "text/event-stream");
        GatewayEncryptorConfig config = bind(props);
        assertThat(config.getSkipUris()).containsExactly("/api/open.*");
        assertThat(config.getSkipMethods()).containsExactly("OPTIONS");
        assertThat(config.getSkipReqContentType()).containsExactly("multipart/form-data");
        assertThat(config.getSkipResContentType()).containsExactly("text/event-stream");
    }

    @Test
    @SuppressWarnings("deprecation")
    void 新旧名字可共存并合并去重() throws Exception {
        Map<String, Object> props = new HashMap<>();
        props.put(GatewayEncryptorConfig.PREFIX + ".skip-uris[0]", "/api/open.*");
        props.put(GatewayEncryptorConfig.PREFIX + ".black-uris[0]", "/api/open.*");
        props.put(GatewayEncryptorConfig.PREFIX + ".black-uris[1]", "/other");
        // 合并发生在 afterPropertiesSet（绑定顺序无关），重复项按值去掉
        assertThat(bind(props).getSkipUris()).containsExactly("/api/open.*", "/other");
    }

    @Test
    void 未配置时名单为空() throws Exception {
        GatewayEncryptorConfig config = bind(new HashMap<String, Object>());
        assertThat(config.getSkipUris()).isEmpty();
        assertThat(config.getSkipMethods()).isEmpty();
        assertThat(config.getSkipReqContentType()).isEmpty();
        assertThat(config.getSkipResContentType()).isEmpty();
    }
}
