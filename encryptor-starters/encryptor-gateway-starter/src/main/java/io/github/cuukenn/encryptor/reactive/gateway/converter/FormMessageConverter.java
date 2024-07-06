package io.github.cuukenn.encryptor.reactive.gateway.converter;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMessage;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.MimeType;
import org.springframework.util.MultiValueMap;
import reactor.core.publisher.Mono;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * @author changgg
 */
@Component
public class FormMessageConverter implements MessageReader<MultiValueMap<String, String>, byte[]>, MessageWriter<MultiValueMap<String, String>, EncryptorDataWrapper> {
    @Override
    public boolean canRead(MediaType mediaType) {
        return MediaType.APPLICATION_FORM_URLENCODED.equals(mediaType);
    }

    @Override
    public RewriteFunction<MultiValueMap<String, String>, byte[]> read() {
        return (exchange, input) -> {
            if (CollUtil.isEmpty(input)) {
                return Mono.empty();
            }
            EncryptorDataWrapper dataWrapper = new JSONObject(input.toSingleValueMap()).toBean(EncryptorDataWrapper.class);
            exchange.getAttributes().put(CoreEncryptorConstant.KEY, dataWrapper.getKey());
            return Mono.just(GatewayKit.getEncryptorFacade(exchange).decrypt(dataWrapper));
        };
    }

    @Override
    public boolean canWrite(MediaType mediaType) {
        return canRead(mediaType);
    }

    @SuppressWarnings("DuplicatedCode")
    @Override
    public RewriteFunction<MultiValueMap<String, String>, EncryptorDataWrapper> write() {
        return (exchange, input) -> {
            if (input == null) {
                return Mono.empty();
            }
            Charset charset = Optional.of(exchange.getResponse()).map(HttpMessage::getHeaders)
                    .map(HttpHeaders::getContentType)
                    .map(MimeType::getCharset)
                    .orElse(StandardCharsets.UTF_8);
            String key = exchange.getAttribute(CoreEncryptorConstant.KEY);
            return Mono.just(GatewayKit.getEncryptorFacade(exchange).encrypt(JSONUtil.toJsonStr(input).getBytes(charset), key));
        };
    }
}
