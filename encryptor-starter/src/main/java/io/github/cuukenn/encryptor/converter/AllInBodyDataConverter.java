package io.github.cuukenn.encryptor.converter;

import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author changgg
 */
public class AllInBodyDataConverter implements DataConverter {
    @Override
    public EncryptorDataWrapper load(HttpServletRequest request, String data) {
        return JSONUtil.toBean(data, EncryptorDataWrapper.class);
    }

    @Override
    public void post(HttpServletResponse response, EncryptorDataWrapper data) throws IOException {
        response.resetBuffer();
        response.getWriter().print(JSONUtil.toJsonStr(data));
    }
}
