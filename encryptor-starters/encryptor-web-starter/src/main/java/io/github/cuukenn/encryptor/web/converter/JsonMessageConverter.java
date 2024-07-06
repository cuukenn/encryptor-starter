package io.github.cuukenn.encryptor.web.converter;

import cn.hutool.http.HttpUtil;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.MimeType;

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
public class JsonMessageConverter implements MessageReader, MessageWriter {
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

    @Override
    public RewriteFunction<byte[], byte[]> write() {
        return (request, response, input) -> {
            String contentType = request.getContentType();
            String charset = Optional.ofNullable(HttpUtil.getCharset(contentType)).orElse(StandardCharsets.UTF_8.name());
            String key = (String) request.getAttribute(CoreEncryptorConstant.KEY);
            EncryptorDataWrapper encryptData = WebContext.current().getEncryptorFacade().encrypt(input, key);
            return JSONUtil.toJsonStr(encryptData).getBytes(Charset.forName(charset));
        };
    }

    @Override
    public RewriteFunction<byte[], byte[]> read() {
        return (request, response, input) -> {
            String contentType = request.getContentType();
            String charset = Optional.ofNullable(HttpUtil.getCharset(contentType)).orElse(StandardCharsets.UTF_8.name());
            String data = new String(input, Charset.forName(charset));
            EncryptorDataWrapper dataWrapper = JSONUtil.toBean(data, EncryptorDataWrapper.class);
            request.setAttribute(CoreEncryptorConstant.KEY, dataWrapper.getKey());
            return WebContext.current().getEncryptorFacade().decrypt(dataWrapper);
        };
    }
}
