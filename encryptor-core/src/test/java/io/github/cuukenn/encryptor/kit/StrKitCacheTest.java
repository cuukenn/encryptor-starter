package io.github.cuukenn.encryptor.kit;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link StrKit} 正则缓存契约测试：同一正则只编译一次，缓存可失效。
 *
 * @author changgg
 */
class StrKitCacheTest {

    @Test
    void 同一正则连续两次复用同一Pattern实例() {
        Pattern first = StrKit.pattern("/pay/.*");
        Pattern second = StrKit.pattern("/pay/.*");

        assertSame(first, second, "同一正则必须复用缓存的 Pattern");
    }

    @Test
    void invalidate后重新编译() {
        Pattern before = StrKit.pattern("/x/.*");
        StrKit.invalidate();
        assertNotSame(before, StrKit.pattern("/x/.*"), "失效后必须重新编译");
    }

    @Test
    void matches是整串匹配且语义与旧实现一致() {
        assertTrue(StrKit.matches("/pay/.*", "/pay/x"));
        assertTrue(StrKit.matches("/pay/.*", "/pay/"));
        assertFalse(StrKit.matches("/pay/.*", "x/pay/y"), "整串匹配：前缀命中不算");
        assertFalse(StrKit.matches("/pay/.*", null));

        assertTrue(StrKit.anyMatch("abc", Collections.singletonList("a.*")));
        assertFalse(StrKit.anyMatch("abc", Collections.singletonList("/z.*")));
    }
}
