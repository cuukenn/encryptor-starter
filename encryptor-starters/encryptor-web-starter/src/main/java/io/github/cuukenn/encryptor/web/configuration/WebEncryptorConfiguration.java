package io.github.cuukenn.encryptor.web.configuration;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
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

import javax.servlet.Filter;
import java.util.Locale;

/**
 * web 侧（servlet）装配：四个过滤器 + v2 协议栈注入。
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
            String clazzPath = filter.getClass().toString().toLowerCase(Locale.ROOT);
            // 配置过滤器的名称，首字母一定要小写，不然拦截了请求后会报错
            this.filterRegistrationBean.setName(clazzPath.substring(clazzPath.lastIndexOf(".")));
            // 不显式传 "/*" 时虽然容器默认匹配全部请求，但语义依赖容器实现；这里显式声明
            this.filterRegistrationBean.addUrlPatterns(patterns.length == 0 ? new String[]{"/*"} : patterns);
            this.filterRegistrationBean.setAsyncSupported(async);
            return this;
        }
    }
}
