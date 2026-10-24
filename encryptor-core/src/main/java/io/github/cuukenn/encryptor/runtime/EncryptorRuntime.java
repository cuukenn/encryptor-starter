package io.github.cuukenn.encryptor.runtime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 运行期开关（进程内热改，不必重启）。
 *
 * <p>旁路是止血开关：某方向被旁路后，该方向的报文原样透传。为避免"热更后仍用旧配置"，
 * 变更会调用所有已注册的失效器（典型：{@code FacadeResolver::invalidate}）。
 *
 * <p>读侧用 volatile 快照：写侧整体替换快照，读者要么看到旧方向的完整状态、
 * 要么看到新方向的完整状态，不会出现"请求旁路、响应未旁路"的混合态；
 * 每次读取即为新值，过滤器应每请求读一次而不是启动期缓存。
 *
 * @author changgg
 */
public class EncryptorRuntime {

    private static final Logger logger = LoggerFactory.getLogger(EncryptorRuntime.class);

    /** 单个快照：两个方向的旁路标志一起换，杜绝混合态（包内可见，测试可断言内部自洽）。 */
    static final class Snapshot {
        final boolean bypassRequest;
        final boolean bypassResponse;

        Snapshot(boolean bypassRequest, boolean bypassResponse) {
            this.bypassRequest = bypassRequest;
            this.bypassResponse = bypassResponse;
        }
    }

    private static final Snapshot INITIAL = new Snapshot(false, false);

    private volatile Snapshot snapshot = INITIAL;
    private final List<Runnable> invalidators = new CopyOnWriteArrayList<>();

    /** 请求方向是否旁路（原样透传，不要求密文）。 */
    public boolean bypassRequest() {
        return snapshot.bypassRequest;
    }

    /** 响应方向是否旁路（不加密，原样返回明文）。 */
    public boolean bypassResponse() {
        return snapshot.bypassResponse;
    }

    /**
     * 设置旁路并触发全部失效器。
     *
     * <p>失效器循环有异常隔离：单个失效器失败只记 WARN，不中断其余失效器——
     * 否则旁路标志已生效而部分缓存未失效，恰好复现"热更后仍用旧配置"。
     */
    public void setBypass(boolean request, boolean response) {
        snapshot = new Snapshot(request, response);
        for (Runnable invalidator : invalidators) {
            try {
                invalidator.run();
            } catch (RuntimeException e) {
                logger.warn("bypass invalidator failed: {}", String.valueOf(invalidator), e);
            }
        }
    }

    /** 注册失效器：旁路变更时被调用。 */
    public void addInvalidator(Runnable invalidator) {
        invalidators.add(invalidator);
    }

    /** 当前快照（包内可见：包内可以原子读取两个方向；测试用它钉住"快照无混合态"）。 */
    Snapshot currentSnapshot() {
        return snapshot;
    }
}
