package io.github.cuukenn.encryptor.reactive.gateway.rewrite;

import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.facade.EncryptorFacadeFactory;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.reactive.converter.DataConverterFactory;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author changgg
 */
public class EncryptorGatewayFilter implements GlobalFilter {
    private final GatewayEncryptorConfig config;
    private final EncryptorFacadeFactory<CryptoConfig> facadeFactory;
    private final DataConverterFactory<CryptoConfig> dataConverterFactory;

    public EncryptorGatewayFilter(GatewayEncryptorConfig config, EncryptorFacadeFactory<CryptoConfig> facadeFactory, DataConverterFactory<CryptoConfig> dataConverterFactory) {
        this.config = config;
        this.facadeFactory = facadeFactory;
        this.dataConverterFactory = dataConverterFactory;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final String uri = exchange.getRequest().getURI().getPath();
        boolean isBlankUri = StrKit.anyMatch(uri, config.getBlackURIs());
        if (isBlankUri) {
            return chain.filter(exchange);
        }
        boolean isBlankMethod = StrKit.anyMatch(exchange.getRequest().getMethodValue(), config.getBlackMethods());
        if (isBlankMethod) {
            return chain.filter(exchange);
        }
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_ENABLE, true);
        MediaType contentType = exchange.getRequest().getHeaders().getContentType();
        boolean isBlankReqContentType = contentType != null && StrKit.anyMatch(contentType.toString(), config.getBlackURIs());
        if (!isBlankReqContentType) {
            exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_REQUEST_ENABLE, true);
        }
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_CONFIG, config);
        String bestMatchStr = StrKit.getBestMatchStr(uri, config.getCryptoConfig().keySet());
        CryptoConfig cryptoConfig = bestMatchStr != null ? config.getCryptoConfig().get(uri) : null;
        GatewayKit.setEncryptorFacade(exchange, this.facadeFactory.apply(cryptoConfig));
        GatewayKit.setEncryptorDataConverter(exchange, this.dataConverterFactory.apply(cryptoConfig));
        return chain.filter(exchange);
    }
}
