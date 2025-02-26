package io.github.cuukenn.encryptor.reactive.gateway.filter.rewrite;

import cn.hutool.core.lang.TypeReference;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Map;

/**
 * 对params参数进行处理
 *
 * @author changgg
 */
public class EncryptorRequestParameterFilter implements GlobalFilter, Ordered {
    private final int order;

    public EncryptorRequestParameterFilter(int order) {
        this.order = order;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!GatewayKit.isReqEncryptorEnable(exchange)) {
            return chain.filter(exchange);
        }
        return new GatewayFilter() {
            @Override
            public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
                ServerHttpRequest request = exchange.getRequest();
                Map<String, String> paramsMap = request.getQueryParams().toSingleValueMap();

                if (paramsMap.isEmpty()) {
                    return chain.filter(exchange);
                }

                EncryptorDataWrapper dataWrapper = new JSONObject(paramsMap).toBean(EncryptorDataWrapper.class);

                exchange.getAttributes().put(CoreEncryptorConstant.KEY, dataWrapper.getKey());

                byte[] decryptData = GatewayKit.getEncryptorFacade(exchange).decrypt(dataWrapper);

                Map<String, String> newParameters = JSONUtil.toBean(new String(decryptData), new TypeReference<Map<String, String>>() {
                }, true);

                MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();

                newParameters.forEach(queryParams::add);

                URI newUri = UriComponentsBuilder.fromUri(request.getURI())
                        .replaceQueryParams(CollectionUtils.toMultiValueMap(queryParams)).build().toUri();

                ServerHttpRequest updatedRequest = exchange.getRequest().mutate().uri(newUri).build();

                return chain.filter(exchange.mutate().request(updatedRequest).build());
            }
        }.filter(exchange, chain);
    }

    @Override
    public int getOrder() {
        return order;
    }
}
