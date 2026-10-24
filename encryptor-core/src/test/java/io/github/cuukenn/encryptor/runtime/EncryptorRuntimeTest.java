package io.github.cuukenn.encryptor.runtime;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
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

    @Test
    void 单个失效器抛异常不中断其余失效器() {
        EncryptorRuntime runtime = new EncryptorRuntime();
        AtomicInteger invalidated = new AtomicInteger();
        runtime.addInvalidator(() -> { throw new IllegalStateException("boom"); });
        runtime.addInvalidator(invalidated::incrementAndGet);

        runtime.setBypass(true, true);

        assertEquals(1, invalidated.get(), "异常只隔离自己，其余失效器必须照常执行");
        assertTrue(runtime.bypassRequest(), "旁路标志仍必须生效");
    }

    @Test
    void 并发换面期间快照永远无混合态() throws Exception {
        // 写侧只发布 (true,true) / (false,false) 两种快照；volatile 整包换面保证读者拿到的
        // 快照内部自洽——不存在 (request=新, response=旧) 的混合快照。
        // （两次独立的字段读允许跨越一次换面，那是语义内的：每次读到的都是当时的完整状态。）
        EncryptorRuntime runtime = new EncryptorRuntime();
        AtomicInteger mixed = new AtomicInteger();
        CountDownLatch stop = new CountDownLatch(1);
        Thread writer = new Thread(() -> {
            while (stop.getCount() > 0) {
                runtime.setBypass(true, true);
                runtime.setBypass(false, false);
            }
        });
        Thread reader = new Thread(() -> {
            while (stop.getCount() > 0) {
                EncryptorRuntime.Snapshot snap = runtime.currentSnapshot();
                if (snap.bypassRequest != snap.bypassResponse) {
                    mixed.incrementAndGet();
                }
            }
        });
        writer.start();
        reader.start();
        Thread.sleep(200);
        stop.countDown();
        writer.join(2000);
        reader.join(2000);
        writer.interrupt();
        assertEquals(0, mixed.get(), "任何已发布的快照内部都必须自洽");
        assertFalse(runtime.bypassRequest());
        assertFalse(runtime.bypassResponse());
    }
}
