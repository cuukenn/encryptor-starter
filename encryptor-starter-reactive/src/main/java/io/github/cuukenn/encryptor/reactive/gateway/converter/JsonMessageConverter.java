package io.github.cuukenn.encryptor.reactive.gateway.converter;

import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMessage;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.MimeType;
import reactor.core.publisher.Mono;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * @author changgg
 */
@Component
public class JsonMessageConverter implements MessageReader<EncryptorDataWrapper, byte[]>, MessageWriter<String, EncryptorDataWrapper> {
    private static final List<MimeType> DEFAULT_MIME_TYPES = Collections.unmodifiableList(
            Arrays.asList(
                    MediaType.APPLICATION_JSON,
                    new MediaType("application", "*+json"),
                    MediaType.APPLICATION_NDJSON));

    @Override
    public boolean canRead(MediaType mediaType) {
        return DEFAULT_MIME_TYPES.stream().anyMatch(x -> x.isCompatibleWith(mediaType));
    }

    @Override
    public boolean canWrite(MediaType mediaType) {
        return canRead(mediaType);
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

    @Override
    public RewriteFunction<EncryptorDataWrapper, byte[]> read() {
        return (exchange, input) -> {
            if (input == null) {
                return Mono.empty();
            }
            exchange.getAttributes().put(CoreEncryptorConstant.KEY, input.getKey());
            return Mono.just(GatewayKit.getEncryptorFacade(exchange).decrypt(input));
        };
    }
}
