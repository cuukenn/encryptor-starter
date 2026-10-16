package io.github.cuukenn.encryptor.web.configuration;

import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.facade.IEncryptorFacadeFactory;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.converter.FormMessageConverter;
import io.github.cuukenn.encryptor.web.converter.JsonMessageConverter;
import io.github.cuukenn.encryptor.web.converter.MessageReader;
import io.github.cuukenn.encryptor.web.converter.MessageWriter;
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
import java.util.List;
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

    /**
     * 消息转换器在自动装配里显式声明，不再用 {@code @ComponentScan} 扫 starter 的包：
     * 扫包会把 starter 内部的 bean 倒进业务上下文，且使用方没有开关能去掉；
     * 这里同时提供 {@code @ConditionalOnMissingBean}，使用方注册同类型 bean 即可覆盖。
     */
    @Bean
    @ConditionalOnMissingBean(FormMessageConverter.class)
    public FormMessageConverter formMessageConverter() {
        return new FormMessageConverter();
    }

    @Bean
    @ConditionalOnMissingBean(JsonMessageConverter.class)
    public JsonMessageConverter jsonMessageConverter() {
        return new JsonMessageConverter();
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnMissingBean(name = "defaultRequestParameterEncryptorFilter")
    @Bean("defaultRequestParameterEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> encryptorRequestParameterFilterFilterRegistrationBean(WebEncryptorConfig config) {
        logger.info("register request parameter encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Filter filter = new EncryptorRequestParameterFilter();
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(filter, config.getFilterConfig().getEncryptorReqParamsFilterOrder(), false);
        return registrationBean;
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnMissingBean(name = "defaultRequestBodyEncryptorFilter")
    @Bean("defaultRequestBodyEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> encryptorRequestBodyFilterFilterRegistrationBean(WebEncryptorConfig config, List<MessageReader> messageReaders) {
        logger.info("register request body encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Filter filter = new EncryptorRequestBodyFilter(messageReaders);
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(filter, config.getFilterConfig().getEncryptorReqBodyFilterOrder(), false);
        return registrationBean;
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnMissingBean(name = "defaultResponseEncryptorFilter")
    @Bean("defaultResponseEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> encryptorResponseFilterFilterRegistrationBean(WebEncryptorConfig config, List<MessageWriter> messageWriters) {
        logger.info("register response encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Filter filter = new EncryptorResponseFilter(messageWriters);
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(filter, config.getFilterConfig().getEncryptorResFilterOrder(), false);
        return registrationBean;
    }

    @ConditionalOnClass(FilterRegistrationBean.class)
    @ConditionalOnMissingBean(name = "defaultWebEncryptorFilter")
    @Bean("defaultWebEncryptorFilter")
    public FilterRegistrationBean<? extends Filter> webEncryptorFilter(EncryptorConfig encryptorConfig, WebEncryptorConfig config, Map<String, IEncryptorFacadeFactory<CryptoConfig>> facadeFactories) {
        logger.info("register gateway encryptor");
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        Builder<Filter> binder = new Builder<>(registrationBean);
        binder.filterConfiguration(new EncryptorWebFilter(config,
                        configL -> {
                            CryptoConfig cryptoConfig = CryptoConfig.getOrDefaultFill(encryptorConfig.getCryptoConfig(), configL);
                            return facadeFactories.get(cryptoConfig.getEncryptorFactory()).apply(cryptoConfig);
                        }),
                config.getFilterConfig().getEncryptorFilterOrder(), false);
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
