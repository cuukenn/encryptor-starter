package io.github.cuukenn.encryptor.facade;

import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link FacadeResolver} 契约测试：按 uri 缓存解析结果 + 失效。
 *
 * @author changgg
 */
class FacadeResolverTest {

    /** 计数假 factory：断言缓存确实生效/确实被清。 */
    static final class CountingFactory implements FacadeResolver.Factory<Object> {
        final AtomicInteger calls = new AtomicInteger();

        @Override
        public Object create(String uri) {
            calls.incrementAndGet();
            return new Object();
        }
    }

    @Test
    void 相同uri复用同一实例且只解析一次() {
        CountingFactory factory = new CountingFactory();
        FacadeResolver<Object> resolver = new FacadeResolver<>(factory);

        Object first = resolver.resolve("/pay/x");
        Object second = resolver.resolve("/pay/x");

        assertSame(first, second, "同一 uri 必须复用缓存实例");
        assertEquals(1, factory.calls.get(), "同一 uri 只解析一次");
    }

    @Test
    void 不同uri各自解析() {
        CountingFactory factory = new CountingFactory();
        FacadeResolver<Object> resolver = new FacadeResolver<>(factory);

        assertNotSame(resolver.resolve("/a"), resolver.resolve("/b"));
        assertEquals(2, factory.calls.get());
    }

    @Test
    void invalidate后重新计算() {
        CountingFactory factory = new CountingFactory();
        FacadeResolver<Object> resolver = new FacadeResolver<>(factory);

        Object before = resolver.resolve("/a");
        resolver.invalidate();
        Object after = resolver.resolve("/a");

        assertNotSame(before, after, "失效后必须重新解析");
        assertEquals(2, factory.calls.get());
    }

    @Test
    void setBypass后resolver重新计算() {
        CountingFactory factory = new CountingFactory();
        FacadeResolver<Object> resolver = new FacadeResolver<>(factory);
        EncryptorRuntime runtime = new EncryptorRuntime();
        runtime.addInvalidator(resolver::invalidate);

        Object before = resolver.resolve("/a");
        assertEquals(1, factory.calls.get());

        runtime.setBypass(true, false);
        Object after = resolver.resolve("/a");

        assertNotSame(before, after, "旁路切换必须连带清缓存，否则热更后仍用旧配置");
        assertEquals(2, factory.calls.get());
        assertTrue(runtime.bypassRequest());
    }
}
