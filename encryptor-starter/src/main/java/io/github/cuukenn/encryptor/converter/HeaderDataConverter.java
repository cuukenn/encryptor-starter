package io.github.cuukenn.encryptor.converter;

import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

/**
 * @author changgg
 */
public class HeaderDataConverter implements DataConverter {
    @Override
    public EncryptorDataWrapper load(HttpServletRequest request, String data) {
        return new EncryptorDataWrapper(
                request.getHeader("x-nonce"),
                Long.valueOf(request.getHeader("x-timestamp")),
                request.getHeader("x-signature"),
                request.getHeader("x-key"),
                JSONUtil.parseObj(data).getStr("data")
        );
    }

    @SuppressWarnings("UastIncorrectHttpHeaderInspection")
    @Override
    public void post(HttpServletResponse response, EncryptorDataWrapper data) throws IOException {
        response.setHeader("x-nonce", data.getNonce());
        response.setHeader("x-timestamp", String.valueOf(data.getTimestamp()));
        response.setHeader("x-signature", data.getNonce());
        response.resetBuffer();
        response.getWriter().print(JSONUtil.toJsonStr(Collections.singletonMap("data", data.getData())));
    }
}
