package io.github.cuukenn.encryptor.reactive.converter;

import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;

/**
 * @author changgg
 */
public class AllInBodyDataConverter implements DataConverter {
    @Override
    public EncryptorDataWrapper load(ServerHttpRequest request, String data) {
        return JSONUtil.toBean(data, EncryptorDataWrapper.class);
    }

    @Override
    public String post(ServerHttpResponse response, EncryptorDataWrapper data) {
        return JSONUtil.toJsonStr(data);
    }
}
