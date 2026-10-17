package io.github.cuukenn.encryptor.reactive.gateway.discovery;

import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.jose.PublicKeyInfo;
import io.github.cuukenn.encryptor.jose.ServerKeyStore;
import io.github.cuukenn.encryptor.reactive.config.DiscoveryConfig;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 网关侧 JWKS 只读发现端点：{@code GET ${discovery.path}} → 只含公钥的 JWKS，网关自己响应、不转发下游。
 *
 * <p><b>必须是 {@link WebFilter} 而不是 GlobalFilter</b>：GlobalFilter 只在"路由已匹配"之后才进入
 * 过滤器链，而发现路径通常没有（也不该有）路由 ⇒ 用 GlobalFilter 时真实网关会直接 404
 * （实测如此，见 ledger T16-R2）。WebFilter 在路由之前执行，无需任何路由即可响应。</p>
 *
 * <p>order 最外层（先于加密过滤器）；enable=false / 非 GET / 路径不匹配时原样放行。密钥库不可变 ⇒
 * JWKS 与 ETag 在构造期定型（换 active-kid = 换密钥库 = 换实例）。</p>
 *
 * @author changgg
 */
public class JwksEndpointFilter implements WebFilter, Ordered {

    private final String path;
    private final boolean enable;
    private final String cacheControl;
    private final byte[] body;
    private final String etag;
    private final int order;

    public JwksEndpointFilter(ServerKeyStore keys, DiscoveryConfig discovery) {
        this(keys, discovery, -14);
    }

    public JwksEndpointFilter(ServerKeyStore keys, DiscoveryConfig discovery, int order) {
        this.path = discovery.getPath();
        this.enable = discovery.isEnable();
        this.cacheControl = "public, max-age=" + discovery.getCacheMaxAgeSeconds();
        this.body = jwksJson(keys).getBytes(StandardCharsets.UTF_8);
        this.etag = "\"" + sha256Hex(this.body) + "\"";
        this.order = order;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (!enable || !"GET".equals(exchange.getRequest().getMethodValue())
            || !path.equals(exchange.getRequest().getPath().value())) {
            return chain.filter(exchange);
        }
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().set(HttpHeaders.ETAG, etag);
        response.getHeaders().set(HttpHeaders.CACHE_CONTROL, cacheControl);
        if (etag.equals(exchange.getRequest().getHeaders().getFirst(HttpHeaders.IF_NONE_MATCH))) {
            response.setStatusCode(HttpStatus.NOT_MODIFIED);
            return response.setComplete();
        }
        response.setStatusCode(HttpStatus.OK);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        DataBuffer buffer = response.bufferFactory().wrap(body);
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return order;
    }

    private static String jwksJson(ServerKeyStore keys) {
        List<Map<String, Object>> jwks = new ArrayList<>();
        for (PublicKeyInfo info : keys.publicKeys()) {
            jwks.add(info.jwk());
        }
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("keys", jwks);
        root.put("activeKid", keys.activeKid());
        return JSONUtil.toJsonStr(root);
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new IllegalStateException("计算 JWKS ETag 失败", e);
        }
    }
}
