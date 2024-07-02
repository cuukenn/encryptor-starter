package io.github.cuukenn.encryptor.reactive.gateway.converter;

import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMessage;
import org.springframework.http.MediaType;
import org.springframework.util.MimeType;
import reactor.core.publisher.Mono;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * @author changgg
 */
public class DefaultMessageConverter implements MessageReader<String, byte[]>, MessageWriter<String, EncryptorDataWrapper> {
    @Override
    public boolean canRead(MediaType mediaType) {
        return false;
    }

    @Override
    public RewriteFunction<String, byte[]> read() {
        return (exchange, input) -> {
            if (input == null) {
                return Mono.empty();
            }
            EncryptorDataWrapper dataWrapper = JSONUtil.toBean(input, EncryptorDataWrapper.class);
            exchange.getAttributes().put(CoreEncryptorConstant.KEY, dataWrapper.getKey());
            return Mono.just(GatewayKit.getEncryptorFacade(exchange).decrypt(dataWrapper));
        };
    }

    @Override
    public boolean canWrite(MediaType mediaType) {
        return false;
    }

    @SuppressWarnings("DuplicatedCode")
    @Override
    public RewriteFunction<String, EncryptorDataWrapper> write() {
        return (exchange, input) -> {
            if (input == null) {
                return Mono.empty();
            }
            Charset charset = Optional.of(exchange.getResponse()).map(HttpMessage::getHeaders)
                    .map(HttpHeaders::getContentType)
                    .map(MimeType::getCharset)
                    .orElse(StandardCharsets.UTF_8);
            String key = exchange.getAttribute(CoreEncryptorConstant.KEY);
            return Mono.just(GatewayKit.getEncryptorFacade(exchange).encrypt(input.getBytes(charset), key));
        };
    }
}
