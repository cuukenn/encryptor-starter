package io.github.cuukenn.encryptor.audit;

import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import io.github.cuukenn.encryptor.jose.JweContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * 多监听器组合：按传入顺序依次回调。
 *
 * <p>单个监听器抛出的 {@link RuntimeException} 会被记录为 WARN 后吞掉，既不影响后续监听器，也不影响
 * 加解密主流程——可观测性代码不能成为业务失败的原因。</p>
 *
 * <p>两侧 starter 在装配 {@code DefaultProtocol} 时，把容器里所有 {@link EncryptorListener}
 * bean 用 {@code ObjectProvider#orderedStream()} 取出后交给本类组合；空集合等价于
 * {@link EncryptorListener#NONE}。</p>
 *
 * @author changgg
 */
public final class CompositeEncryptorListener implements EncryptorListener {

    private static final Logger logger = LoggerFactory.getLogger(CompositeEncryptorListener.class);

    private final List<EncryptorListener> listeners;

    private CompositeEncryptorListener(List<EncryptorListener> listeners) {
        this.listeners = listeners;
    }

    /**
     * 组合监听器；{@code null}/空集合（或只含 {@code null}/{@link EncryptorListener#NONE}）
     * 返回 {@link EncryptorListener#NONE}。
     *
     * <p>即使只有一个监听器也会返回组合器，以保证该监听器的异常不会影响主流程。</p>
     */
    public static EncryptorListener of(Collection<? extends EncryptorListener> listeners) {
        if (listeners == null || listeners.isEmpty()) {
            return EncryptorListener.NONE;
        }
        List<EncryptorListener> copy = new ArrayList<>(listeners.size());
        for (EncryptorListener listener : listeners) {
            if (listener != null && listener != EncryptorListener.NONE) {
                copy.add(listener);
            }
        }
        if (copy.isEmpty()) {
            return EncryptorListener.NONE;
        }
        return new CompositeEncryptorListener(Collections.unmodifiableList(copy));
    }

    @Override
    public void onDecryptSuccess(JweContext context) {
        for (EncryptorListener listener : listeners) {
            try {
                listener.onDecryptSuccess(context);
            } catch (RuntimeException e) {
                logFailure("onDecryptSuccess", listener, e);
            }
        }
    }

    @Override
    public void onDecryptFailure(EncryptorFailure failure, Throwable cause) {
        for (EncryptorListener listener : listeners) {
            try {
                listener.onDecryptFailure(failure, cause);
            } catch (RuntimeException e) {
                logFailure("onDecryptFailure", listener, e);
            }
        }
    }

    @Override
    public void onEncryptFailure(EncryptorFailure failure, Throwable cause) {
        for (EncryptorListener listener : listeners) {
            try {
                listener.onEncryptFailure(failure, cause);
            } catch (RuntimeException e) {
                logFailure("onEncryptFailure", listener, e);
            }
        }
    }

    /** 监听器异常只记录、不外抛：可观测性回调不得影响加解密主流程。 */
    private static void logFailure(String callback, EncryptorListener listener, RuntimeException cause) {
        logger.warn("EncryptorListener 回调异常（已忽略，不影响加解密）: callback={}, listener={}",
            callback, listener.getClass().getName(), cause);
    }
}
