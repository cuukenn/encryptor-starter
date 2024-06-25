package io.github.cuukenn.encryptor.web;

import cn.hutool.core.lang.TypeReference;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.converter.DataConverter;
import io.github.cuukenn.encryptor.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
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
    private final EncryptorFacade encryptorEncoder;
    private final DataConverter dataConverter;

    public EncryptorRequestParameterFilter(EncryptorFacade encryptorEncoder, DataConverter dataConverter) {
        this.encryptorEncoder = encryptorEncoder;
        this.dataConverter = dataConverter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        filterChain.doFilter(new HttpServletRequestWrapper(request) {
            private Map<String, String[]> newParameters = null;

            @Override
            public Enumeration<String> getParameterNames() {
                if (newParameters == null) {
                    newParameters = getDecryptParameters(request);
                }
                return Collections.enumeration(newParameters.keySet());
            }

            @Override
            public String[] getParameterValues(String name) {
                if (newParameters == null) {
                    newParameters = getDecryptParameters(request);
                }
                return newParameters.get(name);
            }

            private Map<String, String[]> getDecryptParameters(HttpServletRequest request) {
                final Map<String, String> parameters = request.getParameterMap().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, x -> x.getValue()[0]));
                if (parameters.isEmpty()) {
                    return Collections.emptyMap();
                }
                EncryptorDataWrapper dataWrapper = dataConverter.load(request, JSONUtil.toJsonStr(parameters));
                String decryptData = encryptorEncoder.decrypt(dataWrapper);
                Map<String, String> map = JSONUtil.toBean(decryptData, new TypeReference<Map<String, String>>() {
                }, true);
                request.setAttribute(EncryptorConstant.KEY, dataWrapper.getKey());
                return map.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, x -> new String[]{x.getValue()}));
            }
        }, response);
    }
}
