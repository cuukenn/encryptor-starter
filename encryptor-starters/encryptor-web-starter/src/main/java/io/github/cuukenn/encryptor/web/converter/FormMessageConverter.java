package io.github.cuukenn.encryptor.web.converter;

import cn.hutool.core.lang.TypeReference;
import cn.hutool.core.net.URLDecoder;
import cn.hutool.http.HttpUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author changgg
 */
@Component
public class FormMessageConverter implements MessageReader, MessageWriter {
    @Override
    public boolean canRead(MediaType mediaType) {
        return MediaType.APPLICATION_FORM_URLENCODED.equals(mediaType);
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
            Map<String, String> map = JSONUtil.toBean(JSONUtil.toJsonStr(encryptData), new TypeReference<Map<String, String>>() {
            }, true);
            return HttpUtil.toParams(map).getBytes(Charset.forName(charset));
        };
    }

    @Override
    public RewriteFunction<byte[], byte[]> read() {
        return (request, response, input) -> {
            String contentType = request.getContentType();
            String charset = Optional.ofNullable(HttpUtil.getCharset(contentType)).orElse(StandardCharsets.UTF_8.name());
            String data = new String(URLDecoder.decode(input), Charset.forName(charset));
            Map<String, String> map = Arrays.stream(data.split("&")).map(x -> {
                int index = x.indexOf("=");
                return new String[]{x.substring(0, index), x.substring(index + 1)};
            }).collect(Collectors.toMap(x -> x[0], x -> x[1], (x1, x2) -> x1));
            EncryptorDataWrapper dataWrapper = new JSONObject(map).toBean(EncryptorDataWrapper.class);
            request.setAttribute(CoreEncryptorConstant.KEY, dataWrapper.getKey());
            return WebContext.current().getEncryptorFacade().decrypt(dataWrapper);
        };
    }
}
