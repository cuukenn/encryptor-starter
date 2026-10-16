package io.github.cuukenn.encryptor.reactive.gateway.filter.rewrite;

import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.facade.IEncryptorFacadeFactory;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.reactive.config.CryptoConfig;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.concurrent.ConcurrentHashMap;

/**
 * @author changgg
 */
public class EncryptorGatewayFilter implements GlobalFilter, Ordered {
    /**
     * 未命中任何 uri 级正则时的缓存键。
     *
     * <p>用 {@code \u0000} 前缀：用户配置的正则 key 不会以 NUL 开头，保证哨兵不会与正则 key 冲突。</p>
     */
    private static final String DEFAULT_CONFIG_CACHE_KEY = "\u0000default";

    private final GatewayEncryptorConfig config;
    private final IEncryptorFacadeFactory<CryptoConfig> facadeFactory;
    private final int order;
    /**
     * 命中的正则 key → facade 的并发缓存。
     *
     * <p>命中的正则 key 唯一决定 {@code CryptoConfig}、也唯一决定 facade（apply 内部会做 RSA 的
     * Base64 解码 + KeySpec + KeyFactory，是这条链路里最贵的部分），所以可直接以它为键复用。
     * 每请求都 apply 会重建 RSA，这里缓存后同一 key 只构建一次。</p>
     *
     * <p>过滤器是单例 bean、facade 本就按单例共享，故多线程并发访问此缓存是安全的
     * （{@link ConcurrentHashMap#computeIfAbsent} 保证同一 key 只会被构建一次）。
     * <b>若将来支持运行期改配置，需要在这里提供失效入口。</b></p>
     */
    private final ConcurrentHashMap<String, EncryptorFacade> facadeCache = new ConcurrentHashMap<>();

    public EncryptorGatewayFilter(GatewayEncryptorConfig config, IEncryptorFacadeFactory<CryptoConfig> facadeFactory, int order) {
        this.config = config;
        this.facadeFactory = facadeFactory;
        this.order = order;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final String uri = exchange.getRequest().getURI().getPath();
        boolean isBlankUri = StrKit.anyMatch(uri, config.getBlackUris());
        if (isBlankUri) {
            return chain.filter(exchange);
        }
        boolean isBlankMethod = StrKit.anyMatch(exchange.getRequest().getMethodValue(), config.getBlackMethods());
        if (isBlankMethod) {
            return chain.filter(exchange);
        }
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_ENABLE, true);
        MediaType contentType = exchange.getRequest().getHeaders().getContentType();
        boolean isBlankReqContentType = contentType != null && StrKit.anyMatch(contentType.toString(), config.getBlackReqContentType());
        if (!isBlankReqContentType) {
            exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_REQUEST_ENABLE, true);
        }
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_CONFIG, config);
        String bestMatchStr = StrKit.getBestMatchStr(uri, config.getCryptoConfig().keySet());
        // 必须用命中的正则 key 取值：用 uri 取值会让 uri 级 crypto-config 永远匹配不到
        CryptoConfig cryptoConfig = bestMatchStr != null ? config.getCryptoConfig().get(bestMatchStr) : null;
        // 命中的正则 key 唯一决定配置、也唯一决定 facade，故直接以它为缓存键复用（未命中用哨兵键）。
        // 若将来支持运行期改配置，需要在此处提供缓存失效入口。
        final String cacheKey = bestMatchStr != null ? bestMatchStr : DEFAULT_CONFIG_CACHE_KEY;
        GatewayKit.setEncryptorFacade(exchange, this.facadeCache.computeIfAbsent(cacheKey, k -> this.facadeFactory.apply(cryptoConfig)));
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return order;
    }
}
