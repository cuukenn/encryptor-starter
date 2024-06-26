package io.github.cuukenn.encryptor.web.configuration;

import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.converter.DataConverter;
import io.github.cuukenn.encryptor.facade.EncryptorFacadeFactory;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
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
import java.util.Map;

/**
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
    public FilterRegistrationBean<? extends Filter> encryptorRequestParameterFilterFilterRegistrationBean() {
        logger.info("register request parameter encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Filter filter = new EncryptorRequestParameterFilter();
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(filter, -1, false);
        return registrationBean;
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnMissingBean(name = "defaultRequestBodyEncryptorFilter")
    @Bean("defaultRequestBodyEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> encryptorRequestBodyFilterFilterRegistrationBean() {
        logger.info("register request body encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Filter filter = new EncryptorRequestBodyFilter();
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(filter, -1, false);
        return registrationBean;
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnMissingBean(name = "defaultResponseEncryptorFilter")
    @Bean("defaultResponseEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> encryptorResponseFilterFilterRegistrationBean() {
        logger.info("register response encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Filter filter = new EncryptorResponseFilter();
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(filter, -1, false);
        return registrationBean;
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnMissingBean(name = "defaultWebEncryptorFilter")
    @Bean("defaultWebEncryptorFilter")
    public EncryptorWebFilter webEncryptorFilter(EncryptorConfig encryptorConfig, WebEncryptorConfig config, Map<String, EncryptorFacadeFactory<CryptoConfig>> facadeFactories, Map<String, DataConverter> dataConverters) {
        logger.info("register gateway encryptor");
        return new EncryptorWebFilter(config,
                configL -> {
                    if (configL == null) {
                        configL = encryptorConfig.getCryptoConfig();
                    }
                    return facadeFactories.get(configL.getEncryptorFactory()).apply(configL);
                },
                configM -> {
                    if (configM == null) {
                        configM = encryptorConfig.getCryptoConfig();
                    }
                    return dataConverters.get(configM.getEncryptorConverter());
                });
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
            this.filterRegistrationBean.addUrlPatterns(patterns); // 配置拦截的请求地址
            this.filterRegistrationBean.setAsyncSupported(async);
            return this;
        }
    }
}
