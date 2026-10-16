package io.github.cuukenn.encryptor.reactive.gateway.filter.rewrite;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import io.github.cuukenn.encryptor.reactive.gateway.constant.GatewayConstant;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 解不开的 query 报文必须收敛成"报文非法"：回 4xx 且不进下游，
 * 而不是把 hutool 的 CryptoException 抛成 500。
 *
 * @author changgg
 */
public class EncryptorRequestParameterFilterTest {
    @Test
    public void test_undecryptable_params_respond_with_failure_status_and_skip_chain() {
        GatewayEncryptorConfig config = new GatewayEncryptorConfig();
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                .get("/test/hello?nonce=n&timestamp=1&signature=sig&key=k&data=d").build());
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_ENABLE, true);
        // P0-6 修完，请求方向用的是独立的 attribute：两个都要置位才进请求解密分支
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_REQUEST_ENABLE, true);
        exchange.getAttributes().put(GatewayConstant.GATEWAY_ENCRYPTOR_CONFIG, config);
        GatewayKit.setEncryptorFacade(exchange, new EncryptorFacade(null, null, null, null) {
            @Override
            public byte[] decrypt(EncryptorDataWrapper data) {
                throw new EncryptorException("request decrypt failed: the request body is not decryptable");
            }
        });

        boolean[] chainCalled = {false};
        new EncryptorRequestParameterFilter(-11)
                .filter(exchange, ex -> {
                    chainCalled[0] = true;
                    return Mono.empty();
                })
                .block();

        Assertions.assertEquals(HttpStatus.BAD_REQUEST, exchange.getResponse().getStatusCode());
        Assertions.assertFalse(chainCalled[0], "报文非法时不能进下游");
    }
}
