package io.github.cuukenn.encryptor.audit;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import io.github.cuukenn.encryptor.jose.JweContext;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link CompositeEncryptorListener} 契约测试：多监听器按注册顺序扇出、互不干扰，
 * 且任何监听器抛异常都不得影响其它监听器或加解密主流程。
 *
 * @author changgg
 */
class CompositeEncryptorListenerTest {

    private static final EncryptorFailure FAILURE = EncryptorFailure.REPLAY;
    private static final JweContext CONTEXT = null;

    @Test
    void 按注册顺序扇出全部回调() {
        List<String> calls = new ArrayList<>();
        EncryptorListener composite = CompositeEncryptorListener.of(Arrays.asList(
            recording("a", calls), recording("b", calls)));

        composite.onDecryptSuccess(CONTEXT);
        composite.onDecryptFailure(FAILURE, null);
        composite.onEncryptFailure(FAILURE, null);

        assertEquals(Arrays.asList(
            "a:success", "b:success",
            "a:decrypt-failure", "b:decrypt-failure",
            "a:encrypt-failure", "b:encrypt-failure"), calls);
    }

    @Test
    void 单个监听器抛异常也不外泄() {
        EncryptorListener composite = CompositeEncryptorListener.of(
            Collections.singletonList(throwing()));

        assertDoesNotThrow(() -> composite.onDecryptSuccess(CONTEXT));
        assertDoesNotThrow(() -> composite.onDecryptFailure(FAILURE, null));
        assertDoesNotThrow(() -> composite.onEncryptFailure(FAILURE, null));
    }

    @Test
    void 一个监听器抛异常不影响其它监听器() {
        List<String> calls = new ArrayList<>();
        EncryptorListener composite = CompositeEncryptorListener.of(Arrays.asList(
            throwing(), recording("after", calls)));

        composite.onDecryptSuccess(CONTEXT);
        composite.onDecryptFailure(FAILURE, null);
        composite.onEncryptFailure(FAILURE, null);

        assertEquals(Arrays.asList(
            "after:success", "after:decrypt-failure", "after:encrypt-failure"), calls);
    }

    @Test
    void 空列表或null等价于NONE() {
        assertSame(EncryptorListener.NONE, CompositeEncryptorListener.of(null));
        assertSame(EncryptorListener.NONE, CompositeEncryptorListener.of(Collections.<EncryptorListener>emptyList()));
        assertSame(EncryptorListener.NONE,
            CompositeEncryptorListener.of(Arrays.asList(null, EncryptorListener.NONE)));
    }

    @Test
    void 监听器异常记录warn日志且带回调名与异常() {
        Logger logger = (Logger) LoggerFactory.getLogger(CompositeEncryptorListener.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            EncryptorListener composite = CompositeEncryptorListener.of(
                Collections.singletonList(throwing()));

            composite.onDecryptSuccess(CONTEXT);
            composite.onDecryptFailure(FAILURE, null);
            composite.onEncryptFailure(FAILURE, null);

            assertEquals(3, appender.list.size(), "三个回调的异常都必须留下日志");
            assertTrue(appender.list.get(0).getFormattedMessage().contains("onDecryptSuccess"));
            assertTrue(appender.list.get(1).getFormattedMessage().contains("onDecryptFailure"));
            assertTrue(appender.list.get(2).getFormattedMessage().contains("onEncryptFailure"));
            for (ILoggingEvent event : appender.list) {
                assertEquals(Level.WARN, event.getLevel());
                assertNotNull(event.getThrowableProxy(), "日志必须带异常栈");
            }
        } finally {
            logger.detachAppender(appender);
        }
    }

    private static EncryptorListener recording(String name, List<String> calls) {
        return new EncryptorListener() {
            @Override
            public void onDecryptSuccess(JweContext context) {
                calls.add(name + ":success");
            }

            @Override
            public void onDecryptFailure(EncryptorFailure failure, Throwable cause) {
                calls.add(name + ":decrypt-failure");
            }

            @Override
            public void onEncryptFailure(EncryptorFailure failure, Throwable cause) {
                calls.add(name + ":encrypt-failure");
            }
        };
    }

    private static EncryptorListener throwing() {
        return new EncryptorListener() {
            @Override
            public void onDecryptSuccess(JweContext context) {
                throw new IllegalStateException("boom");
            }

            @Override
            public void onDecryptFailure(EncryptorFailure failure, Throwable cause) {
                throw new IllegalStateException("boom");
            }

            @Override
            public void onEncryptFailure(EncryptorFailure failure, Throwable cause) {
                throw new IllegalStateException("boom");
            }
        };
    }
}
