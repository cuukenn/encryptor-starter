package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.facade.IEncryptorFacadeFactory;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author changgg
 */
public class EncryptorWebFilter extends OncePerRequestFilter {
    /**
     * 未命中任何 uri 级正则时的缓存键。
     *
     * <p>用 {@code \u0000} 前缀：用户配置的正则 key 不会以 NUL 开头，保证哨兵不会与正则 key 冲突。</p>
     */
    private static final String DEFAULT_CONFIG_CACHE_KEY = "\u0000default";

    private final WebEncryptorConfig config;
    private final IEncryptorFacadeFactory<CryptoConfig> facadeFactory;
    /**
     * 命中的正则 key → facade 的并发缓存。
     *
     * <p>命中的正则 key 唯一决定 {@code CryptoConfig}、也唯一决定 facade（apply 内部会做 RSA 的
     * Base64 解码 + KeySpec + KeyFactory，是这条链路里最贵的部分），所以可直接以它为键复用。
     * 每请求都 apply 会重建 RSA，这里缓存后同一 key 只构建一次。</p>
     *
     * <p>过滤器是单例 bean，缓存生命周期与之相同（随进程存活）。<b>若将来支持运行期改配置，
     * 需要在这里提供失效入口（清空或按 key 驱逐），否则仍会用旧配置的 facade。</b></p>
     */
    private final ConcurrentHashMap<String, EncryptorFacade> facadeCache = new ConcurrentHashMap<>();

    public EncryptorWebFilter(WebEncryptorConfig config, IEncryptorFacadeFactory<CryptoConfig> facadeFactory) {
        this.config = config;
        this.facadeFactory = facadeFactory;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            final String uri = request.getRequestURI();
            boolean isBlankUri = StrKit.anyMatch(uri, config.getBlackUris());
            if (isBlankUri) {
                filterChain.doFilter(request, response);
                return;
            }
            boolean isBlankMethod = StrKit.anyMatch(request.getMethod(), config.getBlackMethods());
            if (isBlankMethod) {
                filterChain.doFilter(request, response);
                return;
            }
            WebContext context = WebContext.current();
            context.setEncryptor(true);
            String contentType = request.getHeader(HttpHeaders.CONTENT_TYPE);
            boolean isBlankReqContentType = contentType != null && StrKit.anyMatch(contentType, config.getBlackReqContentType());
            if (!isBlankReqContentType) {
                context.setReqEncryptor(true);
            }
            context.setConfig(config);
            String bestMatchStr = StrKit.getBestMatchStr(uri, config.getCryptoConfig().keySet());
            // 必须用命中的正则 key 取值：用 uri 取值会让 uri 级 crypto-config 永远匹配不到
            CryptoConfig cryptoConfig = bestMatchStr != null ? config.getCryptoConfig().get(bestMatchStr) : null;
            // 命中的正则 key 唯一决定配置、也唯一决定 facade，故直接以它为缓存键复用（未命中用哨兵键）。
            // 若将来支持运行期改配置，需要在此处提供缓存失效入口。
            final String cacheKey = bestMatchStr != null ? bestMatchStr : DEFAULT_CONFIG_CACHE_KEY;
            context.setEncryptorFacade(this.facadeCache.computeIfAbsent(cacheKey, k -> this.facadeFactory.apply(cryptoConfig)));
            filterChain.doFilter(request, response);
        } finally {
            // 请求结束必须清理上下文：Servlet 线程池会复用线程，
            // 否则上一个请求的 EncryptorFacade / config / 标志位会泄漏到下一个请求
            WebContext.clear();
        }
    }
}
