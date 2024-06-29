package io.github.cuukenn.encryptor.web.filter;

import cn.hutool.core.lang.TypeReference;
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
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
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
        EncryptorDataWrapper dataWrapper = WebContext.current().getDataConverter().load(request, JSONUtil.toJsonStr(parameters));
        byte[] decryptData = WebContext.current().getEncryptorFacade().decrypt(dataWrapper);
        Map<String, String> map = JSONUtil.toBean(new String(decryptData), new TypeReference<Map<String, String>>() {
        }, true);
        request.setAttribute(CoreEncryptorConstant.KEY, dataWrapper.getKey());
        return map.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, x -> new String[]{x.getValue()}));
    }
}
