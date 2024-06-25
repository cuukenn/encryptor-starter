package io.github.cuukenn.encryptor.configuration;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.converter.DataConverter;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.web.EncryptorRequestBodyFilter;
import io.github.cuukenn.encryptor.web.EncryptorRequestParameterFilter;
import io.github.cuukenn.encryptor.web.EncryptorResponseFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.Locale;

/**
 * @author changgg
 */
@ConditionalOnProperty(prefix = EncryptorConfig.PREFIX + ".web", name = "enable", havingValue = "true", matchIfMissing = true)
@Configuration
public class WebEncryptorConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(WebEncryptorConfiguration.class);

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnBean(value = {EncryptorEncoder.class, SignerEncoder.class})
    @ConditionalOnMissingBean(name = "defaultRequestParameterEncryptorFilter")
    @Bean("defaultRequestParameterEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> encryptorRequestParameterFilterFilterRegistrationBean(EncryptorFacade encryptorFacade, DataConverter dataConverter) {
        logger.info("register request parameter encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Filter filter = new EncryptorRequestParameterFilter(encryptorFacade, dataConverter);
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(filter, -1, false);
        return registrationBean;
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnBean(value = {EncryptorEncoder.class, SignerEncoder.class})
    @ConditionalOnMissingBean(name = "defaultRequestBodyEncryptorFilter")
    @Bean("defaultRequestBodyEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> encryptorRequestBodyFilterFilterRegistrationBean(EncryptorFacade encryptorFacade, DataConverter dataConverter) {
        logger.info("register request body encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Filter filter = new EncryptorRequestBodyFilter(encryptorFacade, dataConverter);
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(filter, -1, false);
        return registrationBean;
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnBean(value = {EncryptorEncoder.class, SignerEncoder.class})
    @ConditionalOnMissingBean(name = "defaultResponseEncryptorFilter")
    @Bean("defaultResponseEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> encryptorResponseFilterFilterRegistrationBean(EncryptorFacade encryptorFacade, DataConverter dataConverter) {
        logger.info("register response encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Filter filter = new EncryptorResponseFilter(encryptorFacade, dataConverter);
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(filter, -1, false);
        return registrationBean;
    }

    private static class Builder<T extends Filter> {

        private final FilterRegistrationBean<T> filterRegistrationBean;

        public Builder(FilterRegistrationBean<T> filterRegistrationBean) {
            this.filterRegistrationBean = filterRegistrationBean;
        }

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
