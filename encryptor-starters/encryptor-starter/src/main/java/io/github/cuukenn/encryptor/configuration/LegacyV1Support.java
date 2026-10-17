package io.github.cuukenn.encryptor.configuration;

import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.digest.MD5;
import cn.hutool.crypto.symmetric.AES;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.config.CryptoConfig;
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

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * v1 自研协议的算法栈（RSA-PKCS1v15 + AES-CBC + MD5-AES 签名）。
 *
 * <p><b>过渡占位</b>：web/gateway 传输层在 T9/T10/T12 重接到 v2 协议前，
 * 这些 bean 仍被 {@code WebEncryptorConfiguration} 等以
 * {@code Map<String, IEncryptorFacadeFactory>} 注入；重接完成后本类随 v1 一并删除。</p>
 *
 * @author changgg
 * @deprecated v2 协议已用 {@code DefaultProtocol} 替代；本类只为过渡期保住上下文可启动。
 */
@Deprecated
public final class LegacyV1Support {

    private LegacyV1Support() {
    }

    public static IEncryptorFacadeFactory<CryptoConfig> defaultFactory(List<CheckerStrategy> checkerStrategies) {
        return config -> {
            EncoderStrategy encoder = new Base64Encoder();
            Function<String, EncryptorStrategy> strategyFunction = params -> {
                JSONObject obj = JSONUtil.parseObj(params);
                return new HtlSymmetricCryptoEncryptor(new AES(obj.getStr("mode"), obj.getStr("padding"), encoder.decode(obj.getStr("key")), Optional.ofNullable(obj.getStr("iv")).map(x -> x.getBytes(StandardCharsets.UTF_8)).orElse(null)));
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
