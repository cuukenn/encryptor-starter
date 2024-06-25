package io.github.cuukenn.encryptor.reactive.gateway.rewrite;

import cn.hutool.core.lang.TypeReference;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.converter.DataConverter;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.springframework.cloud.gateway.support.GatewayToStringStyler.filterToStringCreator;

/**
 * 对params参数进行处理
 *
 * @author changgg
 */
public class EncryptorRequestParameterGatewayFilterFactory extends AbstractGatewayFilterFactory<AbstractGatewayFilterFactory.NameConfig> {
    private final EncryptorFacade encryptorEncoder;
    private final DataConverter dataConverter;

    public EncryptorRequestParameterGatewayFilterFactory(EncryptorFacade encryptorEncoder, DataConverter dataConverter) {
        this.encryptorEncoder = encryptorEncoder;
        this.dataConverter = dataConverter;
    }

    @Override
    public GatewayFilter apply(NameConfig config) {
        return new GatewayFilter() {
            @Override
            public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
                ServerHttpRequest request = exchange.getRequest();
                Map<String, String> paramsMap = request.getQueryParams().toSingleValueMap();

                if (paramsMap.isEmpty()) {
                    return chain.filter(exchange);
                }

                EncryptorDataWrapper dataWrapper = dataConverter.load(request, JSONUtil.toJsonStr(paramsMap));

                exchange.getAttributes().put(EncryptorConstant.KEY, dataWrapper.getKey());

                String decryptData = encryptorEncoder.decrypt(dataWrapper);

                Map<String, String> newParameters = JSONUtil.toBean(decryptData, new TypeReference<Map<String, String>>() {
                }, true);

                MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();

                newParameters.forEach(queryParams::add);

                URI newUri = UriComponentsBuilder.fromUri(request.getURI())
                        .replaceQueryParams(CollectionUtils.toMultiValueMap(queryParams)).build().toUri();

                ServerHttpRequest updatedRequest = exchange.getRequest().mutate().uri(newUri).build();

                return chain.filter(exchange.mutate().request(updatedRequest).build());
            }

            @Override
            public String toString() {
                return filterToStringCreator(EncryptorRequestParameterGatewayFilterFactory.this)
                        .append("name", config.getName()).toString();
            }
        };
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Collections.singletonList(NAME_KEY);
    }
}
