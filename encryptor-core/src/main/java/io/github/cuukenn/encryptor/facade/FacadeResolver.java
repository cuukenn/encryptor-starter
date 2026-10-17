package io.github.cuukenn.encryptor.facade;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 按 uri 解析并缓存"该 uri 的处理对象"，支持整体失效。
 *
 * <p>泛型：既可缓存 v1 的 {@code EncryptorFacade}，也可缓存新协议的 per-uri 处理对象
 * （密钥/套件/策略的作用域），配置或运行期开关变更时调用 {@link #invalidate()} 重新计算。
 *
 * @param <T> 被缓存的对象类型
 * @author changgg
 */
public class FacadeResolver<T> {

    /** 解析器：按 uri 构造对象。 */
    public interface Factory<T> {

        /**
         * 构造该 uri 的处理对象。
         *
         * @param uri 规范化后的请求路径
         */
        T create(String uri);
    }

    private final Factory<T> factory;
    private final Map<String, T> cache = new ConcurrentHashMap<>();

    public FacadeResolver(Factory<T> factory) {
        this.factory = factory;
    }

    /** 取该 uri 的处理对象（缓存命中则复用）。 */
    public T resolve(String uri) {
        T existing = cache.get(uri);
        if (existing != null) {
            return existing;
        }
        return cache.computeIfAbsent(uri, factory::create);
    }

    /** 清空缓存，下一次 resolve 重新计算。 */
    public void invalidate() {
        cache.clear();
    }
}
