package io.github.cuukenn.encryptor.runtime;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 运行期开关（进程内热改，不必重启）。
 *
 * <p>旁路是止血开关：某方向被旁路后，该方向的报文原样透传。为避免"热更后仍用旧配置"，
 * 变更会调用所有已注册的失效器（典型：{@code FacadeResolver::invalidate}）。
 *
 * <p>读侧用 {@link AtomicBoolean}，保证同一进程内下一次读取即为新值；
 * 过滤器应每请求读一次，而不是启动期缓存。
 *
 * @author changgg
 */
public class EncryptorRuntime {

    private final AtomicBoolean bypassRequest = new AtomicBoolean(false);
    private final AtomicBoolean bypassResponse = new AtomicBoolean(false);
    private final List<Runnable> invalidators = new CopyOnWriteArrayList<>();

    /** 请求方向是否旁路（原样透传，不要求密文）。 */
    public boolean bypassRequest() {
        return bypassRequest.get();
    }

    /** 响应方向是否旁路（不加密，原样返回明文）。 */
    public boolean bypassResponse() {
        return bypassResponse.get();
    }

    /** 设置旁路并触发全部失效器。 */
    public void setBypass(boolean request, boolean response) {
        bypassRequest.set(request);
        bypassResponse.set(response);
        for (Runnable invalidator : invalidators) {
            invalidator.run();
        }
    }

    /** 注册失效器：旁路变更时被调用。 */
    public void addInvalidator(Runnable invalidator) {
        invalidators.add(invalidator);
    }
}
