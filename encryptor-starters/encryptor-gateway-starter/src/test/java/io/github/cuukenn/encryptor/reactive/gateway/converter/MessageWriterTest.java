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
import org.reactivestreams.Publisher;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

/**
 * 网关响应方向：响应内容类型黑名单只能在"响应头已经回来、正在组装响应体"的那一刻判定。
 * 过滤器入口处 exchange.getResponse() 还是空的（下游请求还没发出去），在那里判定永远不生效。
 *
 * @author changgg
 */
public class MessageWriterTest {
    private static final String BLACK_CONTENT_TYPE = "application/octet-stream";

    /**
     * @param result 非 null 时返回固定结果；null 表示"一旦被调用就失败"（黑名单响应不该走加密）
     */
    private static MockServerWebExchange exchange(EncryptorDataWrapper result) {
        GatewayEncryptorConfig config = new GatewayEncryptorConfig();
        config.setBlackResContentType(Collections.singletonList(BLACK_CONTENT_TYPE));

        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test/hello").build());
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_ENABLE, true);
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_CONFIG, config);
        GatewayKit.setEncryptorFacade(exchange, new EncryptorFacade(null, null, null, null) {
            @Override
            public EncryptorDataWrapper encrypt(byte[] data, String key) {
                if (result == null) {
                    throw new AssertionError("black-res-content-type 命中的响应不允许被加密");
                }
                return result;
            }
        });
        return exchange;
    }

    @Test
    public void test_blacklisted_response_content_type_is_not_encrypted() {
        MockServerWebExchange exchange = exchange(null);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_OCTET_STREAM);

        Publisher<?> result = new DefaultMessageConverter().write().apply(exchange, "plain-body");
        Object output = Mono.from(result).block();

        // 响应体必须原样放行
        Assertions.assertEquals("plain-body", new String((byte[]) output, StandardCharsets.UTF_8));
    }

    @Test
    public void test_encryptable_response_content_type_is_encrypted() {
        EncryptorDataWrapper wrapper = new EncryptorDataWrapper("nonce", 1L, "sig", "key", "data");
        MockServerWebExchange exchange = exchange(wrapper);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        // 响应加密的前提：这次请求协商出过 key（加密请求解密后写入 x-key attribute）
        exchange.getAttributes().put(CoreEncryptorConstant.KEY, "key");

        Publisher<?> result = new DefaultMessageConverter().write().apply(exchange, "plain-body");
        Object output = Mono.from(result).block();

        Assertions.assertEquals(JSONUtil.toJsonStr(wrapper), new String((byte[]) output, StandardCharsets.UTF_8));
    }
}
