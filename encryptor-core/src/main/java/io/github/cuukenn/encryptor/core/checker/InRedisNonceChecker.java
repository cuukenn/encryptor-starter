package io.github.cuukenn.encryptor.core.checker;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.core.CheckerStrategy;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

/**
 * @author changgg
 */
public class InRedisNonceChecker implements CheckerStrategy {
    private final RedisTemplate<Object, Object> redisTemplate;
    private final Duration offsetDuration;

    public InRedisNonceChecker(RedisTemplate<Object, Object> redisTemplate, Duration offsetDuration) {
        this.redisTemplate = redisTemplate;
        this.offsetDuration = offsetDuration;
    }

    @Override
    public void check(EncryptorDataWrapper data) {
        final String nonce = data.getNonce();
        if (redisTemplate.opsForValue().get(nonce) != null) {
            throw new EncryptorException("request replay");
        }
        if (System.currentTimeMillis() - data.getTimestamp() >= offsetDuration.get(ChronoUnit.SECONDS) * 1000L) {
            throw new EncryptorException("request out of time or client time error");
        }
        redisTemplate.opsForValue().set(nonce, true, offsetDuration);
    }
}
