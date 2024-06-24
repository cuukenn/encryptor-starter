package com.github.cuukenn.demo.encrypt.lectotype.core.checker;

import cn.hutool.cache.Cache;
import cn.hutool.cache.CacheUtil;
import com.github.cuukenn.demo.encrypt.lectotype.EncryptorException;
import com.github.cuukenn.demo.encrypt.lectotype.core.CheckerStrategy;
import com.github.cuukenn.demo.encrypt.lectotype.pojo.EncryptorDataWrapper;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

/**
 * @author changgg
 */
public class InMemoryNonceChecker implements CheckerStrategy {
    private final Cache<String, Boolean> caches;
    private final Duration offsetDuration;

    public InMemoryNonceChecker(int capacity, Duration offsetDuration) {
        this.caches = CacheUtil.newLRUCache(capacity);
        this.offsetDuration = offsetDuration;
    }

    @Override
    public void check(EncryptorDataWrapper data) {
        final String nonce = data.getNonce();
        if (caches.containsKey(nonce)) {
            throw new EncryptorException("request replay");
        }
        if (System.currentTimeMillis() - data.getTimestamp() >= offsetDuration.get(ChronoUnit.SECONDS) * 1000L) {
            throw new EncryptorException("request out of time or client time error");
        }
        caches.put(nonce, true, offsetDuration.get(ChronoUnit.SECONDS) * 1000L);
    }
}
