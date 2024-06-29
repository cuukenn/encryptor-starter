package io.github.cuukenn.encryptor.reactive.configuration;

import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.digest.MD5;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.core.CheckerStrategy;
import io.github.cuukenn.encryptor.core.EncoderStrategy;
import io.github.cuukenn.encryptor.core.EncryptorStrategy;
import io.github.cuukenn.encryptor.core.digester.HtlDigester;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.HexEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.core.encryptor.HtlASymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.encryptor.HtlSymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.signer.DigestWithEncryptSigner;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.facade.IEncryptorFacadeFactory;
import io.github.cuukenn.encryptor.reactive.config.CryptoConfig;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.reactive.converter.AllInOneDataConverter;
import io.github.cuukenn.encryptor.reactive.converter.DataConverter;
import io.github.cuukenn.encryptor.reactive.converter.HeaderDataConverter;
import io.github.cuukenn.encryptor.reactive.gateway.configuration.GatewayEncryptorConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * @author changgg
 */
@EnableConfigurationProperties(EncryptorConfig.class)
@ConditionalOnProperty(prefix = EncryptorConfig.PREFIX, name = "enable", havingValue = "true", matchIfMissing = true)
@Import({GatewayEncryptorConfiguration.class})
@Configuration(proxyBeanMethods = false)
public class EncryptorReactiveAutoConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorReactiveAutoConfiguration.class);

    @Bean(EncryptorConstant.DEFAULT_ENCRYPTOR_FACTORY)
    public IEncryptorFacadeFactory<CryptoConfig> encryptorFacadeFactory(List<CheckerStrategy> checkerStrategies) {
        logger.info("register default encryptor factory, used checker:[{}]", checkerStrategies);
        return ascConfig -> {
            Function<String, EncryptorStrategy> strategyFunction = params -> {
                JSONObject obj = JSONUtil.parseObj(params);
                return new HtlSymmetricCryptoEncryptor(new AES(obj.getStr("mode"), obj.getStr("padding"), obj.getBytes("key"), Optional.ofNullable(obj.getStr("iv")).map(String::getBytes).orElse(null)));
            };
            EncoderStrategy encoder = new HexEncoder();
            return new EncryptorFacade(
                    new EncryptorEncoder(new HtlASymmetricCryptoEncryptor(new RSA(ascConfig.getAlgorithm(), ascConfig.getPrivateKey(), ascConfig.getPublicKey())), encoder),
                    params -> new EncryptorEncoder(strategyFunction.apply(params), encoder),
                    params -> new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()), strategyFunction.apply(params)), encoder),
                    checkerStrategies
            );
        };
    }

    @Bean(EncryptorConstant.ALL_IN_ONE_CONVERTER)
    public DataConverter allInOneConverter() {
        return new AllInOneDataConverter();
    }

    @Bean(EncryptorConstant.HEADER_CONVERTER)
    public DataConverter headerDataConverter() {
        return new HeaderDataConverter();
    }
}

