package io.github.cuukenn.encryptor.reactive.gateway.runtime;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 容器生命周期回归：boundedElastic 的线程是非守护线程，上下文关闭必须 dispose，
 * 否则测试/热重启会残留 {@code encryptor-crypto-N} 线程。
 *
 * @author changgg
 */
class CryptoExecutorLifecycleTest {

    @Test
    void 上下文关闭时释放调度器() {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.registerBean(CryptoExecutor.class, CryptoExecutor::create);
        context.refresh();
        CryptoExecutor executor = context.getBean(CryptoExecutor.class);

        assertThat(executor.scheduler().isDisposed()).isFalse();
        context.close();

        assertThat(executor.scheduler().isDisposed()).isTrue();
    }
}
