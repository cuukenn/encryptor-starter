package io.github.cuukenn.encryptor.core.checker;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

/**
 * @author changgg
 */
public class InRedisNonceCheckerTest {
    private static EncryptorDataWrapper wrapper(String nonce, Long timestamp) {
        EncryptorDataWrapper data = new EncryptorDataWrapper();
        data.setNonce(nonce);
        data.setTimestamp(timestamp);
        return data;
    }

    @SuppressWarnings("unchecked")
    private static RedisTemplate<Object, Object> mockTemplate(ValueOperations<Object, Object> operations) {
        RedisTemplate<Object, Object> redisTemplate = Mockito.mock(RedisTemplate.class);
        Mockito.when(redisTemplate.opsForValue()).thenReturn(operations);
        return redisTemplate;
    }

    @Test
    @SuppressWarnings("unchecked")
    public void test_same_nonce_rejected_atomically() {
        ValueOperations<Object, Object> operations = Mockito.mock(ValueOperations.class);
        Duration offset = Duration.ofSeconds(30);
        Mockito.when(operations.setIfAbsent(Mockito.any(), Mockito.any(), Mockito.any(Duration.class))).thenReturn(true, false);
        InRedisNonceChecker checker = new InRedisNonceChecker(mockTemplate(operations), offset);
        long now = System.currentTimeMillis();
        checker.check(wrapper("nonce-1", now));
        Assertions.assertThrows(EncryptorException.class, () -> checker.check(wrapper("nonce-1", now)));
        // 两次都必须是 setIfAbsent：先 get 再 set 的实现无法原子地去重
        Mockito.verify(operations, Mockito.times(2)).setIfAbsent("nonce-1", true, offset);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void test_out_of_time_request_does_not_touch_redis() {
        ValueOperations<Object, Object> operations = Mockito.mock(ValueOperations.class);
        InRedisNonceChecker checker = new InRedisNonceChecker(mockTemplate(operations), Duration.ofSeconds(30));
        long future = System.currentTimeMillis() + Duration.ofMinutes(1).toMillis();
        Assertions.assertThrows(EncryptorException.class, () -> checker.check(wrapper("nonce-future", future)));
        // 时间戳不合法的请求不应该占用 redis 里的 nonce
        Mockito.verify(operations, Mockito.never()).setIfAbsent(Mockito.any(), Mockito.any(), Mockito.any(Duration.class));
    }
}
