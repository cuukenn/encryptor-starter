package io.github.cuukenn.encryptor.reactive.gateway.kit;

import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.reactive.converter.DataConverter;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;

import java.util.Objects;

/**
 * @author changgg
 */
public class GatewayKit {
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public static boolean isReqEncryptorEnable(ServerWebExchange exchange) {
        return exchange.getAttribute(GatewayConstant.GATEWAY_ENCRYPTOR_ENABLE) != null && exchange.getAttribute(GatewayConstant.GATEWAY_ENCRYPTOR_REQUEST_ENABLE) != null;
    }

    public static boolean isResEncryptorEnable(ServerWebExchange exchange) {
        MediaType contentType = exchange.getResponse().getHeaders().getContentType();
        GatewayEncryptorConfig config = exchange.getAttribute(GatewayConstant.GATEWAY_ENCRYPTOR_CONFIG);
        return exchange.getAttribute(GatewayConstant.GATEWAY_ENCRYPTOR_ENABLE) != null && !(contentType != null && StrKit.anyMatch(contentType.toString(), Objects.requireNonNull(config).getBlackResponseContentType()));
    }

    public static EncryptorFacade getEncryptorFacade(ServerWebExchange exchange) {
        return exchange.getAttribute(GatewayConstant.GATEWAY_ENCRYPTOR_BEAN);
    }

    public static void setEncryptorFacade(ServerWebExchange exchange, EncryptorFacade facade) {
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_BEAN, facade);
    }

    public static DataConverter getEncryptorDataConverter(ServerWebExchange exchange) {
        return exchange.getAttribute(GatewayConstant.GATEWAY_ENCRYPTOR_DATA_CONVERTER_BEAN);
    }

    public static void setEncryptorDataConverter(ServerWebExchange exchange, DataConverter facade) {
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_DATA_CONVERTER_BEAN, facade);
    }
}
