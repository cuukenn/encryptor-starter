package io.github.cuukenn.encryptor.core.checker;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.core.CheckerStrategy;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;

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
        final Long timestamp = data.getTimestamp();
        if (timestamp == null) {
            throw new EncryptorException("request timestamp is missing");
        }
        // 时窗必须对称：只判断"过去"的话，客户端把时间戳写成未来即可绕过校验
        if (Math.abs(System.currentTimeMillis() - timestamp) >= offsetDuration.toMillis()) {
            throw new EncryptorException("request out of time or client time error");
        }
        // setIfAbsent 是原子的：先 get 再 set 会让两个并发的同 nonce 请求同时通过防重放校验
        Boolean firstSet = redisTemplate.opsForValue().setIfAbsent(nonce, true, offsetDuration);
        if (!Boolean.TRUE.equals(firstSet)) {
            throw new EncryptorException("request replay");
        }
    }
}
