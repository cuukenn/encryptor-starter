package io.github.cuukenn.encryptor.configuration;

import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.digest.MD5;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.core.CheckerStrategy;
import io.github.cuukenn.encryptor.core.EncoderStrategy;
import io.github.cuukenn.encryptor.core.EncryptorStrategy;
import io.github.cuukenn.encryptor.core.digester.HtlDigester;
import io.github.cuukenn.encryptor.core.encoder.Base64Encoder;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.core.encryptor.HtlASymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.encryptor.HtlSymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.signer.DigestWithEncryptSigner;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.facade.IEncryptorFacadeFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * @author changgg
 */
@EnableConfigurationProperties(EncryptorConfig.class)
@ConditionalOnProperty(prefix = EncryptorConfig.PREFIX, name = "enable", havingValue = "true", matchIfMissing = true)
@Configuration(proxyBeanMethods = false)
public class EncryptorAutoConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorAutoConfiguration.class);

    @Bean(EncryptorConstant.DEFAULT_ENCRYPTOR_FACTORY)
    public IEncryptorFacadeFactory<CryptoConfig> encryptorFacadeFactory(List<CheckerStrategy> checkerStrategies) {
        logger.info("register default encryptor factory, used checker:[{}]", checkerStrategies);
        return config -> {
            EncoderStrategy encoder = new Base64Encoder();
            Function<String, EncryptorStrategy> strategyFunction = params -> {
                JSONObject obj = JSONUtil.parseObj(params);
                return new HtlSymmetricCryptoEncryptor(new AES(obj.getStr("mode"), obj.getStr("padding"), encoder.decode(obj.getStr("key")), Optional.ofNullable(obj.getStr("iv")).map(String::getBytes).orElse(null)));
            };
            return new EncryptorFacade(
                    new EncryptorEncoder(new HtlASymmetricCryptoEncryptor(new RSA(config.getAlgorithm(), config.getPrivateKey(), config.getPublicKey())), encoder),
                    params -> new EncryptorEncoder(strategyFunction.apply(params), encoder),
                    params -> new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()), strategyFunction.apply(params)), encoder),
                    checkerStrategies
            );
        };
    }
}
