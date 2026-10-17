package io.github.cuukenn.encryptor.runtime;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link EncryptorRuntime} 契约测试：运行期旁路开关（进程内立即生效，无须重启）。
 *
 * @author changgg
 */
class EncryptorRuntimeTest {

    @Test
    void 默认两个方向都不旁路() {
        EncryptorRuntime runtime = new EncryptorRuntime();
        assertFalse(runtime.bypassRequest());
        assertFalse(runtime.bypassResponse());
    }

    @Test
    void setBypass同进程内下一次读取即为新值() {
        EncryptorRuntime runtime = new EncryptorRuntime();

        runtime.setBypass(true, false);
        assertTrue(runtime.bypassRequest(), "请求方向旁路必须立刻生效（不重启）");
        assertFalse(runtime.bypassResponse());

        runtime.setBypass(false, true);
        assertFalse(runtime.bypassRequest());
        assertTrue(runtime.bypassResponse(), "响应方向旁路必须立刻生效（不重启）");

        runtime.setBypass(false, false);
        assertFalse(runtime.bypassRequest());
        assertFalse(runtime.bypassResponse());
    }

    @Test
    void setBypass触发全部失效器() {
        EncryptorRuntime runtime = new EncryptorRuntime();
        AtomicInteger invalidated = new AtomicInteger();
        runtime.addInvalidator(invalidated::incrementAndGet);
        runtime.addInvalidator(invalidated::incrementAndGet);

        runtime.setBypass(true, true);
        assertEquals(2, invalidated.get(), "每个失效器都必须被调用一次");

        runtime.setBypass(false, false);
        assertEquals(4, invalidated.get(), "每次变更都要触发");
    }

    @Test
    void 未注册失效器时setBypass不报错() {
        assertDoesNotThrow(() -> new EncryptorRuntime().setBypass(true, true));
    }
}
