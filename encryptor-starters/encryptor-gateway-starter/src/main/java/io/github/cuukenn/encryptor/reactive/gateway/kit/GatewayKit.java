package io.github.cuukenn.encryptor.reactive.gateway.kit;

import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

/**
 * @author changgg
 */
public class GatewayKit {
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public static boolean isReqEncryptorEnable(ServerWebExchange exchange) {
        return exchange.getAttribute(GatewayConstant.GATEWAY_ENCRYPTOR_ENABLE) != null && exchange.getAttribute(GatewayConstant.GATEWAY_ENCRYPTOR_REQUEST_ENABLE) != null;
    }

    /**
     * 响应方向是否需要加密。
     *
     * <p><b>只能在"组装响应体"的那一刻调用</b>（各 {@code MessageWriter#write()} 内部）：
     * 它要看响应 Content-Type，而下游响应头只有到那时才回来。在网关过滤器入口处调用时
     * {@code exchange.getResponse()} 还是空的，{@code black-res-content-type} 会永远不生效
     * （见 open-issues.md P1-9）。</p>
     */
    public static boolean isResEncryptorEnable(ServerWebExchange exchange) {
        MediaType contentType = exchange.getResponse().getHeaders().getContentType();
        GatewayEncryptorConfig config = exchange.getAttribute(GatewayConstant.GATEWAY_ENCRYPTOR_CONFIG);
        return exchange.getAttribute(GatewayConstant.GATEWAY_ENCRYPTOR_ENABLE) != null && !(contentType != null && StrKit.anyMatch(contentType.toString(), Objects.requireNonNull(config).getBlackResContentType()));
    }

    public static EncryptorFacade getEncryptorFacade(ServerWebExchange exchange) {
        return exchange.getAttribute(GatewayConstant.GATEWAY_ENCRYPTOR_BEAN);
    }

    public static void setEncryptorFacade(ServerWebExchange exchange, EncryptorFacade facade) {
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_BEAN, facade);
    }

    /**
     * 报文非法（解不开 / 验签失败）时的统一出口：按配置的状态码（默认 400）结束响应，不再往下游走。
     *
     * <p>之前是让 {@code CryptoException} 一路冒泡，客户端拿到 500 且无法与"服务端故障"区分。</p>
     */
    public static Mono<Void> failure(ServerWebExchange exchange) {
        GatewayEncryptorConfig config = exchange.getAttribute(GatewayConstant.GATEWAY_ENCRYPTOR_CONFIG);
        int status = config == null ? 400 : config.getFailureStatus();
        exchange.getResponse().setStatusCode(HttpStatus.valueOf(status));
        return exchange.getResponse().setComplete();
    }
}
