package io.github.cuukenn.encryptor.reactive.gateway.filter.rewrite;

import io.github.cuukenn.encryptor.facade.IEncryptorFacadeFactory;
import io.github.cuukenn.encryptor.reactive.config.CryptoConfig;
import io.github.cuukenn.encryptor.reactive.gateway.config.GatewayEncryptorConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 验证 uri 级 crypto-config 取的是"命中的正则 key"对应的配置，而不是用原始 uri 取值
 *
 * @author changgg
 */
public class EncryptorGatewayFilterTest {
    @Test
    public void test_crypto_config_used_by_matched_regex_key() {
        CryptoConfig expected = new CryptoConfig();
        Map<String, CryptoConfig> cryptoConfig = new LinkedHashMap<>();
        cryptoConfig.put("^/test/hello.*", expected);

        GatewayEncryptorConfig config = new GatewayEncryptorConfig();
        config.setCryptoConfig(cryptoConfig);

        final CryptoConfig[] captured = new CryptoConfig[1];
        IEncryptorFacadeFactory<CryptoConfig> facadeFactory = cryptoConf -> {
            captured[0] = cryptoConf;
            return null;
        };

        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test/hello").build());
        EncryptorGatewayFilter filter = new EncryptorGatewayFilter(config, facadeFactory, -13);
        filter.filter(exchange, ex -> Mono.empty()).block();

        Assertions.assertSame(expected, captured[0]);
    }
}
