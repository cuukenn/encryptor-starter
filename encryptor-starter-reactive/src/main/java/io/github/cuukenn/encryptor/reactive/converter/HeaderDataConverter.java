package io.github.cuukenn.encryptor.reactive.converter;

import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;

import java.util.Collections;
import java.util.Objects;

/**
 * @author changgg
 */
public class HeaderDataConverter implements DataConverter {
    @SuppressWarnings("UastIncorrectHttpHeaderInspection")
    @Override
    public EncryptorDataWrapper load(ServerHttpRequest request, String data) {
        HttpHeaders headers = request.getHeaders();
        return new EncryptorDataWrapper(
                headers.getFirst("x-nonce"),
                Long.valueOf(Objects.requireNonNull(headers.getFirst("x-timestamp"))),
                headers.getFirst("x-signature"),
                headers.getFirst("x-key"),
                JSONUtil.parseObj(data).getStr("data")
        );
    }

    @SuppressWarnings("UastIncorrectHttpHeaderInspection")
    @Override
    public String post(ServerHttpResponse response, EncryptorDataWrapper data) {
        HttpHeaders headers = response.getHeaders();
        headers.set("x-nonce", data.getNonce());
        headers.set("x-timestamp", String.valueOf(data.getTimestamp()));
        headers.set("x-signature", data.getNonce());
        return JSONUtil.toJsonStr(Collections.singletonMap("data", data.getData()));
    }
}
