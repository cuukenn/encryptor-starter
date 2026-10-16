package io.github.cuukenn.encryptor;

import cn.hutool.core.util.IdUtil;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.facade.IEncryptorFacadeFactory;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.config.CryptoConfig;
import io.github.cuukenn.encryptor.reactive.configuration.EncryptorReactiveAutoConfiguration;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * @author changgg
 */
public class HttpTest {
    private static final Logger logger = LoggerFactory.getLogger(HttpTest.class);
    private static final String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKlPT4bCuAmY7vPxJjXnU9hACtV2VfrxvY8tcfuzQJs8ipSoBmKDAPYPlCIAhZDMtartp/gvnVm9iflUk8hwo5Cpfzp7dZ+gGePT5HoT1Fs5AS6+Rq1mf+tfRZY2o6Er5TqBrdhYR8A15P2AYBp/ckfto4zrYFB3WB2woqdwt5jtAgMBAAECgYABSsnUa/ZZRbxbypUxknSOhnKZYsqmMc5yDMqSvVv6s1FqxVuDHfUrFj8EVr+uNWRqNl/H955k+cWB9yDHm1XMOM01iOBevXdWOW2OGeYB/IsPmpwnkK5frjU5FNxWAe96C/7btJLV2YmVo/bcTkYk+6Oyzh//h/SZdHNdJ13vAQJBAO0VSe73QzQ6z0wwcFy+E/G/mLCD+YK4vJRKRadO3EBGXByMxTMF5bxyKbwPRve9TQPaIcKScaC6HT5MI6DQ14ECQQC20as8yEK+PI/qg5HitRb4PVS1QJu/TH/2HC339QoMjmn30SBnF38B4nxN6XgZhLyUpRtnhMUDwxHok/deD1dtAkA0MpS1jTD5pd0QHDYQ5TSE7DcU3emoUz4JtBSD0oQBjrwm+QNNyYWcKNJxejeYwc/cAkGekhl8Vp2rop3RgUmBAkBkw6fYNqDi7cp8/cu44wsoA9XemR+/DtEwu1Ny6bKCPTSXDMMJT2AHj+fnoZk6p3ixjVdPdVSJwEjsojGjvFz5AkEAmoSHxY23ytLrkMggR1c9SQ4O0rZfURLRYTGG2t4EutQzpLmwalye8vvUOKKNWk4GauH085FvFw4iFhVAnRl71A==";
    private static final String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCpT0+GwrgJmO7z8SY151PYQArVdlX68b2PLXH7s0CbPIqUqAZigwD2D5QiAIWQzLWq7af4L51ZvYn5VJPIcKOQqX86e3WfoBnj0+R6E9RbOQEuvkatZn/rX0WWNqOhK+U6ga3YWEfANeT9gGAaf3JH7aOM62BQd1gdsKKncLeY7QIDAQAB";

    @Test
    public void test_get() {
        String body = test_get_all_in_one("http://127.0.0.1:8080/test/hello", Collections.singletonMap("name", "小明"));
        // 网关把 /test/** 路由到下游（127.0.0.1:8081），下游 GET /test/hello 返回 "Hello, " + name
        Assertions.assertTrue(body.contains("Hello"), "响应应包含下游返回的 Hello，实际为: " + body);
        Assertions.assertTrue(body.contains("小明"), "响应应回显请求参数 name=小明，实际为: " + body);
    }

    @Test
    public void test_post() {
        String body = test_post_all_in_one("http://127.0.0.1:8080/test/hello", Collections.singletonMap("name", "小明"));
        // 下游 POST /test/hello(JSON) 返回 "Hello, " + data（data 是 {name=小明}）
        Assertions.assertTrue(body.contains("Hello"), "响应应包含下游返回的 Hello，实际为: " + body);
        Assertions.assertTrue(body.contains("小明"), "响应应回显请求体中的 name=小明，实际为: " + body);
    }

    @SuppressWarnings("SameParameterValue")
    private String test_get_all_in_one(String url, Map<String, Object> params) {
        EncryptorReactiveAutoConfiguration configuration = new EncryptorReactiveAutoConfiguration();
        IEncryptorFacadeFactory<CryptoConfig> facadeFactory = configuration.encryptorFacadeFactory(Collections.emptyList());
        CryptoConfig cryptoConfig = new CryptoConfig();
        cryptoConfig.setPublicKey(publicKey);
        cryptoConfig.setPrivateKey(privateKey);
        EncryptorFacade facade = facadeFactory.apply(cryptoConfig);

        //加密及签名
        final String key = IdUtil.fastSimpleUUID();
        Map<String, String> keyParams = new LinkedHashMap<>();
        keyParams.put("key", key);
        keyParams.put("mode", Mode.CBC.name());
        keyParams.put("padding", Padding.PKCS5Padding.name());
        keyParams.put("iv", (RandomUtil.randomString(16)));
        final String xKey = facade.getNegotiateEncoder().encrypt(JSONUtil.toJsonStr(keyParams).getBytes());
        logger.info("xKey: {}, decryptKey: {}", xKey, new String(facade.getNegotiateEncoder().decrypt(xKey)));

        EncryptorDataWrapper encrypt = facade.encrypt(JSONUtil.toJsonStr(params).getBytes(), xKey);
        logger.info(JSONUtil.toJsonStr(encrypt));

        logger.info("localDecrypted:{}", new String(facade.decrypt(encrypt)));

        // WebTestClient 会把 URI 当成已编码串直接发送，所以这里自己严格 URL 编码：
        // base64 里的 '+' 若不编码成 %2B，网关侧 getQueryParams() 会把它解成空格 -> 解密失败
        Map<String, Object> query = new LinkedHashMap<>();
        query.put("nonce", encrypt.getNonce());
        query.put("timestamp", encrypt.getTimestamp());
        query.put("signature", encrypt.getSignature());
        query.put("key", encrypt.getKey());
        query.put("data", encrypt.getData());
        StringBuilder fullUrl = new StringBuilder(url);
        boolean first = true;
        for (Map.Entry<String, Object> entry : query.entrySet()) {
            fullUrl.append(first ? '?' : '&');
            first = false;
            fullUrl.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(String.valueOf(entry.getValue()), StandardCharsets.UTF_8));
        }
        URI uri = URI.create(fullUrl.toString());

        final String[] plaintext = new String[1];
        WebTestClient client = WebTestClient.bindToServer().build();
        client.get().uri(uri).exchange()
                .expectStatus().isOk()
                .expectBody(byte[].class).consumeWith(res -> {
                    byte[] raw = Objects.requireNonNull(res.getResponseBody());
                    logger.info("raw:{}", new String(raw));
                    plaintext[0] = new String(facade.decrypt(JSONUtil.toBean(new String(raw), EncryptorDataWrapper.class)));
                    logger.info("decryptedData:{}", plaintext[0]);
                });
        return plaintext[0];
    }

    @SuppressWarnings("SameParameterValue")
    private String test_post_all_in_one(String url, Map<String, Object> data) {
        EncryptorReactiveAutoConfiguration configuration = new EncryptorReactiveAutoConfiguration();
        IEncryptorFacadeFactory<CryptoConfig> facadeFactory = configuration.encryptorFacadeFactory(Collections.emptyList());
        CryptoConfig cryptoConfig = new CryptoConfig();
        cryptoConfig.setPublicKey(publicKey);
        cryptoConfig.setPrivateKey(privateKey);
        EncryptorFacade facade = facadeFactory.apply(cryptoConfig);

        //加密及签名
        final String key = IdUtil.fastSimpleUUID();
        Map<String, String> keyParams = new LinkedHashMap<>();
        keyParams.put("key", key);
        keyParams.put("mode", Mode.CBC.name());
        keyParams.put("padding", Padding.PKCS5Padding.name());
        keyParams.put("iv", (RandomUtil.randomString(16)));
        final String xKey = facade.getNegotiateEncoder().encrypt(JSONUtil.toJsonStr(keyParams).getBytes());
        logger.info("xKey: {}, decryptKey: {}", xKey, new String(facade.getNegotiateEncoder().decrypt(xKey)));

        EncryptorDataWrapper encrypt = facade.encrypt(JSONUtil.toJsonStr(data).getBytes(), xKey);
        logger.info(JSONUtil.toJsonStr(encrypt));

        logger.info("localDecrypted:{}", new String(facade.decrypt(encrypt)));

        final String[] plaintext = new String[1];
        WebTestClient client = WebTestClient.bindToServer().build();
        client.post().uri(url)
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .body((clientHttpRequest, context) -> clientHttpRequest.writeWith(Mono.just(clientHttpRequest.bufferFactory().wrap(JSONUtil.toJsonStr(encrypt).getBytes())))).exchange()
                .expectStatus().isOk()
                .expectBody(byte[].class).consumeWith(res -> {
                    byte[] raw = Objects.requireNonNull(res.getResponseBody());
                    logger.info("raw:{}", new String(raw));
                    plaintext[0] = new String(facade.decrypt(JSONUtil.toBean(new String(raw), EncryptorDataWrapper.class)));
                    logger.info("decryptedData:{}", plaintext[0]);
                });
        return plaintext[0];
    }
}
