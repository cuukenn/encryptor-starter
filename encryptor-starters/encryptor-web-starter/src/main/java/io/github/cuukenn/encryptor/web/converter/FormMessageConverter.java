package io.github.cuukenn.encryptor.web.converter;

import cn.hutool.core.lang.TypeReference;
import cn.hutool.core.net.URLDecoder;
import cn.hutool.core.util.StrUtil;
import cn.hutool.http.HttpUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.http.MediaType;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author changgg
 */
public class FormMessageConverter implements MessageReader, MessageWriter {
    @Override
    public boolean canRead(MediaType mediaType) {
        // 不能用 equals：application/x-www-form-urlencoded;charset=UTF-8 与常量不等
        return MediaType.APPLICATION_FORM_URLENCODED.isCompatibleWith(mediaType);
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
            EncryptorDataWrapper dataWrapper;
            try {
                Map<String, String> map = parseForm(data);
                dataWrapper = new JSONObject(map).toBean(EncryptorDataWrapper.class);
            } catch (RuntimeException e) {
                // 报文不是合法密文结构：算"报文非法"，由过滤器回 4xx
                throw new EncryptorException("request body is not a valid encrypted payload", e);
            }
            request.setAttribute(CoreEncryptorConstant.KEY, dataWrapper.getKey());
            return WebContext.current().getEncryptorFacade().decrypt(dataWrapper);
        };
    }

    /**
     * 解析 form 表单文本，兼容没有 '=' 的段落（如 "a=1&broken"）与重复 key
     *
     * @param data 表单文本
     * @return 参数
     */
    static Map<String, String> parseForm(String data) {
        return Arrays.stream(data.split("&")).filter(StrUtil::isNotBlank).map(x -> {
            int index = x.indexOf("=");
            return index < 0 ? new String[]{x, ""} : new String[]{x.substring(0, index), x.substring(index + 1)};
        }).collect(Collectors.toMap(x -> x[0], x -> x[1], (x1, x2) -> x1));
    }
}
