package io.github.cuukenn.encryptor.web.filter;

import cn.hutool.core.lang.TypeReference;
import cn.hutool.core.net.URLDecoder;
import cn.hutool.core.util.StrUtil;
import cn.hutool.http.ContentType;
import cn.hutool.http.HttpUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 解密request parameters
 *
 * @author changgg
 */
public class EncryptorRequestParameterFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!WebContext.current().isReqEncryptor()) {
            filterChain.doFilter(request, response);
            return;
        }
        Map<String, String[]> decryptParameters = getDecryptParameters(request);
        filterChain.doFilter(new HttpServletRequestWrapper(request) {
            @Override
            public Enumeration<String> getParameterNames() {
                return Collections.enumeration(decryptParameters.keySet());
            }

            @Override
            public String[] getParameterValues(String name) {
                return decryptParameters.get(name);
            }


        }, response);
    }

    private Map<String, String[]> getDecryptParameters(HttpServletRequest request) {
        final Map<String, String> parameters = request.getParameterMap().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, x -> x.getValue()[0]));
        if (parameters.isEmpty()) {
            return Collections.emptyMap();
        }
        EncryptorDataWrapper dataWrapper = new JSONObject(parameters).toBean(EncryptorDataWrapper.class);
        byte[] decryptData = WebContext.current().getEncryptorFacade().decrypt(dataWrapper);
        String contentType = request.getContentType();
        String charset = Optional.ofNullable(HttpUtil.getCharset(contentType)).orElse(StandardCharsets.UTF_8.name());
        String data = new String(decryptData, Charset.forName(charset));
        if (ContentType.isFormUrlEncode(contentType)) {
            data = URLDecoder.decode(data, Charset.forName(charset));
            data = JSONUtil.toJsonStr(parseFormData(data));
        }
        Map<String, String> map = JSONUtil.toBean(data, new TypeReference<Map<String, String>>() {
        }, true);
        request.setAttribute(CoreEncryptorConstant.KEY, dataWrapper.getKey());
        return map.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, x -> new String[]{x.getValue()}));
    }

    /**
     * 解析 form 表单文本：兼容没有 '=' 的段落与重复 key
     * （原实现遇到 "a=1&broken" 会抛 StringIndexOutOfBoundsException，遇到重复 key 会抛 IllegalStateException）
     *
     * @param data 表单文本
     * @return 参数
     */
    static Map<Object, Object> parseFormData(String data) {
        return Arrays.stream(data.split("&")).filter(StrUtil::isNotBlank).map(x -> {
            int index = x.indexOf('=');
            return index < 0 ? new String[]{x, ""} : new String[]{x.substring(0, index), x.substring(index + 1)};
        }).collect(Collectors.toMap(x -> x[0], x -> x[1], (x1, x2) -> x1));
    }
}
