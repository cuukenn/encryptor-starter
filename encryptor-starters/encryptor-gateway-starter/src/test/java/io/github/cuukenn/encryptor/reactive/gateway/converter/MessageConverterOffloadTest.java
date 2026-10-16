package io.github.cuukenn.encryptor.reactive.gateway.converter;

import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * RSA/AES 是同步阻塞运算，必须从 Netty event loop 切到弹性线程池执行（open-issues.md P1-13）。
 * 这里用"被调用时当前线程名"作为证据钉住这一点。
 *
 * @author changgg
 */
public class MessageConverterOffloadTest {

    private static MockServerWebExchange exchange() {
        GatewayEncryptorConfig config = new GatewayEncryptorConfig();
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/test/hello").build());
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_ENABLE, true);
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_CONFIG, config);
        return exchange;
    }

    @Test
    public void test_decrypt_runs_off_event_loop_thread() {
        MockServerWebExchange exchange = exchange();
        final String[] threadName = new String[1];
        GatewayKit.setEncryptorFacade(exchange, new EncryptorFacade(null, null, null, null) {
            @Override
            public byte[] decrypt(EncryptorDataWrapper data) {
                threadName[0] = Thread.currentThread().getName();
                return data.getData().getBytes(StandardCharsets.UTF_8);
            }
        });

        EncryptorDataWrapper wrapper = new EncryptorDataWrapper("nonce", 1L, "sig", "key", "plain");
        Object output = Mono.from(new DefaultMessageConverter().read().apply(exchange, JSONUtil.toJsonStr(wrapper))).block();

        Assertions.assertEquals("plain", new String((byte[]) output, StandardCharsets.UTF_8));
        Assertions.assertNotNull(threadName[0]);
        Assertions.assertTrue(threadName[0].contains("boundedElastic"),
                "RSA 解密必须在弹性线程池执行，实际线程: " + threadName[0]);
    }

    @Test
    public void test_encrypt_runs_off_event_loop_thread() {
        MockServerWebExchange exchange = exchange();
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getAttributes().put(CoreEncryptorConstant.KEY, "key");
        final String[] threadName = new String[1];
        GatewayKit.setEncryptorFacade(exchange, new EncryptorFacade(null, null, null, null) {
            @Override
            public EncryptorDataWrapper encrypt(byte[] data, String key) {
                threadName[0] = Thread.currentThread().getName();
                return new EncryptorDataWrapper("n", 1L, "s", key, new String(data, StandardCharsets.UTF_8));
            }
        });

        Object output = Mono.from(new DefaultMessageConverter().write().apply(exchange, "plain-body")).block();

        Assertions.assertNotNull(output);
        Assertions.assertNotNull(threadName[0]);
        Assertions.assertTrue(threadName[0].contains("boundedElastic"),
                "AES/RSA 加密必须在弹性线程池执行，实际线程: " + threadName[0]);
    }
}
