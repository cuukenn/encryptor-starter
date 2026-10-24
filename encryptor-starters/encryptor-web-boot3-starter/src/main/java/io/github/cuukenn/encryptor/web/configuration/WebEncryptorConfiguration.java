package io.github.cuukenn.encryptor.web.configuration;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import java.util.Map;
import java.util.List;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.config.WebFilterConfig;
import io.github.cuukenn.encryptor.web.discovery.JwksEndpointFilter;
import io.github.cuukenn.encryptor.web.filter.EncryptorRequestBodyFilter;
import io.github.cuukenn.encryptor.web.filter.EncryptorRequestParameterFilter;
import io.github.cuukenn.encryptor.web.filter.EncryptorResponseFilter;
import io.github.cuukenn.encryptor.web.filter.EncryptorWebFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import jakarta.servlet.Filter;
import java.util.Locale;

/**
 * web 侧（servlet）装配：五个过滤器 + v2 协议栈注入。
 *
 * <p>链序取自 {@code WebFilterConfig}（<b>顺序是载荷契约</b>：门面过滤器在参数/请求体视图过滤器之外，
 * 响应过滤器在门面内层），见 {@code FilterChainOrderTest}——那里直接取本类的注册 bean 按 order 组装链，
 * 钉死顺序，改默认值即红。</p>
 *
 * @author changgg
 */
@ConditionalOnProperty(prefix = EncryptorConfig.PREFIX + ".web", name = "enable", havingValue = "true", matchIfMissing = true)
@Configuration
@EnableConfigurationProperties(WebEncryptorConfig.class)
public class WebEncryptorConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(WebEncryptorConfiguration.class);

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnMissingBean(name = "defaultRequestParameterEncryptorFilter")
    @Bean("defaultRequestParameterEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> encryptorRequestParameterFilterFilterRegistrationBean(WebEncryptorConfig config) {
        logger.info("register request parameter encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(new EncryptorRequestParameterFilter(), config.getFilterConfig().getEncryptorReqParamsFilterOrder(), true);
        return registrationBean;
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnMissingBean(name = "defaultRequestBodyEncryptorFilter")
    @Bean("defaultRequestBodyEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> encryptorRequestBodyFilterFilterRegistrationBean(WebEncryptorConfig config) {
        logger.info("register request body encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(new EncryptorRequestBodyFilter(), config.getFilterConfig().getEncryptorReqBodyFilterOrder(), true);
        return registrationBean;
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnMissingBean(name = "defaultResponseEncryptorFilter")
    @Bean("defaultResponseEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> encryptorResponseFilterFilterRegistrationBean(WebEncryptorConfig config, EncryptorConfig encryptorConfig, DefaultProtocol protocolStack, EncryptorRuntime runtime) {
        logger.info("register response encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(new EncryptorResponseFilter(encryptorConfig, protocolStack, runtime), config.getFilterConfig().getEncryptorResFilterOrder(), true);
        return registrationBean;
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnMissingBean(name = "defaultWebEncryptorFilter")
    @Bean("defaultWebEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> webEncryptorFilter(WebEncryptorConfig config, EncryptorConfig encryptorConfig, DefaultProtocol protocolStack, EncryptorRuntime runtime) {
        logger.info("register web encryptor");
        validateFilterOrder(config.getFilterConfig());
        validateCryptoKids(config, protocolStack);
        // 用户覆盖 EncryptorRuntime bean 时，配置的启动期 bypass 写在 protocol 内部实例上，
        // 而过滤器读的是覆盖 bean——热开关/旁路配置会静默落空，必须在启动期拦住
        if (runtime != protocolStack.runtime()) {
            throw new EncryptorException("注册的 EncryptorRuntime bean 与 DefaultProtocol 内部实例不是同一对象："
                + "启动期 bypass 配置与 setBypass 热开关将只作用于其中一个。"
                + "请删除自定义 EncryptorRuntime bean（默认 bean 即 protocol.runtime()），"
                + "或改用 protocol.runtime() 返回的实例");
        }
        WebFilterConfig orders = config.getFilterConfig();
        logger.info("加密过滤器链序: jwks={}, 门面={}, 参数={}, 请求体={}, 响应={}（链序契约: jwks < 门面 < 参数 < 请求体 < 响应；"
            + "下游过滤器要在明文视图内运行时，order 必须落在门面与响应之间）",
            orders.getJwksFilterOrder(), orders.getEncryptorFilterOrder(), orders.getEncryptorReqParamsFilterOrder(),
            orders.getEncryptorReqBodyFilterOrder(), orders.getEncryptorResFilterOrder());
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(new EncryptorWebFilter(config, encryptorConfig, protocolStack, runtime),
                config.getFilterConfig().getEncryptorFilterOrder(), true);
        return registrationBean;
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnMissingBean(name = "defaultJwksDiscoveryFilter")
    @Bean("defaultJwksDiscoveryFilter")
    public FilterRegistrationBean<? extends Filter> jwksDiscoveryFilter(WebEncryptorConfig config, EncryptorConfig encryptorConfig, DefaultProtocol protocolStack) {
        logger.info("register jwks discovery endpoint, path: {}", encryptorConfig.getDiscovery().getPath());
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(new JwksEndpointFilter(protocolStack.keys(), encryptorConfig.getDiscovery()),
                config.getFilterConfig().getJwksFilterOrder(), true);
        return registrationBean;
    }

    private static class Builder<T extends Filter> {

        private final FilterRegistrationBean<T> filterRegistrationBean;

        public Builder(FilterRegistrationBean<T> filterRegistrationBean) {
            this.filterRegistrationBean = filterRegistrationBean;
        }

        @SuppressWarnings("UnusedReturnValue")
        public Builder<T> filterConfiguration(T filter, int order, boolean async, String... patterns) {
            this.filterRegistrationBean.setFilter(filter); // 设置过滤器
            this.filterRegistrationBean.setOrder(order); // 设置启动顺序
            // 注册名用简单类名的小写形式；不能对 getClass().toString() 做 substring(lastIndexOf("."))，
            // 那样会得到 ".encryptorwebfilter"（前导点 + 丢掉类名语义）。
            this.filterRegistrationBean.setName(filter.getClass().getSimpleName().toLowerCase(Locale.ROOT));
            // 不显式传 "/*" 时虽然容器默认匹配全部请求，但语义依赖容器实现；这里显式声明
            this.filterRegistrationBean.addUrlPatterns(patterns.length == 0 ? new String[]{"/*"} : patterns);
            this.filterRegistrationBean.setAsyncSupported(async);
            return this;
        }
    }

    /**
     * {@code crypto-config} 的 kid 必须真实存在：拼错时白名单会让该 uri 下所有请求恒定 400，
     * 启动期就报错比流量上才发现便宜得多。
     */
    static void validateCryptoKids(WebEncryptorConfig config, DefaultProtocol protocol) {
        if (config.getCryptoConfig() != null) {
            for (Map.Entry<String, List<String>> entry : config.getCryptoConfig().entrySet()) {
                if (entry.getValue() == null) {
                    continue;
                }
                for (String kid : entry.getValue()) {
                    if (!protocol.keys().contains(kid)) {
                        throw new EncryptorException("encryptor.config.web.crypto-config[" + entry.getKey()
                            + "] 引用了不存在的 kid: " + kid);
                    }
                }
            }
        }
        if (config.getRoutes() != null) {
            for (Map.Entry<String, io.github.cuukenn.encryptor.config.base.RouteRule> entry
                : config.getRoutes().entrySet()) {
                List<String> kids = entry.getValue() == null ? null : entry.getValue().getKids();
                if (kids == null) {
                    continue;
                }
                for (String kid : kids) {
                    if (!protocol.keys().contains(kid)) {
                        throw new EncryptorException("encryptor.config.web.routes[" + entry.getKey()
                            + "].kids 引用了不存在的 kid: " + kid);
                    }
                }
            }
        }
    }

    /**
     * 过滤器 order 是载荷契约：order 全部可配（下游应用插入自己的过滤器时必须调），但相对顺序
     * 错了不会报错，而是<b>静默退化</b>——视图过滤器在门面之外看到的是密文原文，响应过滤器
     * 在门面/参数过滤器之外拿不到 CEK 时 fail-open 放行明文。因此链序契约必须在启动期校验，
     * 而不是只靠钉住默认值的单测。
     */
    static void validateFilterOrder(WebFilterConfig orders) {
        boolean ok = orders.getJwksFilterOrder() < orders.getEncryptorFilterOrder()
            && orders.getEncryptorFilterOrder() < orders.getEncryptorReqParamsFilterOrder()
            && orders.getEncryptorReqParamsFilterOrder() < orders.getEncryptorReqBodyFilterOrder()
            && orders.getEncryptorReqBodyFilterOrder() < orders.getEncryptorResFilterOrder();
        if (!ok) {
            throw new EncryptorException("过滤器 order 违反链序契约: jwks("
                + orders.getJwksFilterOrder() + ") < 门面(" + orders.getEncryptorFilterOrder()
                + ") < 参数(" + orders.getEncryptorReqParamsFilterOrder() + ") < 请求体("
                + orders.getEncryptorReqBodyFilterOrder() + ") < 响应(" + orders.getEncryptorResFilterOrder()
                + ")。调整顺序时必须整体保持该相对关系，否则加密链路会静默失效");
        }
    }
}
