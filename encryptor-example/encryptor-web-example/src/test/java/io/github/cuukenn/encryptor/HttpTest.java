package io.github.cuukenn.encryptor;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.lang.TypeReference;
import cn.hutool.core.util.IdUtil;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.http.HttpRequest;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.configuration.EncryptorAutoConfiguration;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.facade.IEncryptorFacadeFactory;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.util.CollectionUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author changgg
 */
public class HttpTest {
    private static final Logger logger = LoggerFactory.getLogger(HttpTest.class);
    private static final String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKlPT4bCuAmY7vPxJjXnU9hACtV2VfrxvY8tcfuzQJs8ipSoBmKDAPYPlCIAhZDMtartp/gvnVm9iflUk8hwo5Cpfzp7dZ+gGePT5HoT1Fs5AS6+Rq1mf+tfRZY2o6Er5TqBrdhYR8A15P2AYBp/ckfto4zrYFB3WB2woqdwt5jtAgMBAAECgYABSsnUa/ZZRbxbypUxknSOhnKZYsqmMc5yDMqSvVv6s1FqxVuDHfUrFj8EVr+uNWRqNl/H955k+cWB9yDHm1XMOM01iOBevXdWOW2OGeYB/IsPmpwnkK5frjU5FNxWAe96C/7btJLV2YmVo/bcTkYk+6Oyzh//h/SZdHNdJ13vAQJBAO0VSe73QzQ6z0wwcFy+E/G/mLCD+YK4vJRKRadO3EBGXByMxTMF5bxyKbwPRve9TQPaIcKScaC6HT5MI6DQ14ECQQC20as8yEK+PI/qg5HitRb4PVS1QJu/TH/2HC339QoMjmn30SBnF38B4nxN6XgZhLyUpRtnhMUDwxHok/deD1dtAkA0MpS1jTD5pd0QHDYQ5TSE7DcU3emoUz4JtBSD0oQBjrwm+QNNyYWcKNJxejeYwc/cAkGekhl8Vp2rop3RgUmBAkBkw6fYNqDi7cp8/cu44wsoA9XemR+/DtEwu1Ny6bKCPTSXDMMJT2AHj+fnoZk6p3ixjVdPdVSJwEjsojGjvFz5AkEAmoSHxY23ytLrkMggR1c9SQ4O0rZfURLRYTGG2t4EutQzpLmwalye8vvUOKKNWk4GauH085FvFw4iFhVAnRl71A==";
    private static final String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCpT0+GwrgJmO7z8SY151PYQArVdlX68b2PLXH7s0CbPIqUqAZigwD2D5QiAIWQzLWq7af4L51ZvYn5VJPIcKOQqX86e3WfoBnj0+R6E9RbOQEuvkatZn/rX0WWNqOhK+U6ga3YWEfANeT9gGAaf3JH7aOM62BQd1gdsKKncLeY7QIDAQAB";

    @Test
    public void test_get() {
        test_get_all_in_one("http://127.0.0.1:8081/test/hello", Collections.singletonMap("name", "小明"));
    }

    @Test
    public void test_post() {
        test_post_all_in_one("http://127.0.0.1:8081/test/hello", Collections.singletonMap("name", "小明"));
    }

    @SuppressWarnings("SameParameterValue")
    private void test_get_all_in_one(String url, Map<String, Object> params) {
        EncryptorAutoConfiguration configuration = new EncryptorAutoConfiguration();
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
        Map<String, List<String>> encryptParams = JSONUtil.toBean(JSONUtil.toJsonStr(encrypt), new TypeReference<Map<String, String>>() {
        }, true).entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, x -> CollUtil.newArrayList(x.getValue())));
        logger.info(JSONUtil.toJsonStr(encrypt));

        logger.info("localDecrypted:{}", new String(facade.decrypt(encrypt)));

        URI uri = UriComponentsBuilder.fromUriString(url)
                .replaceQueryParams(CollectionUtils.toMultiValueMap(encryptParams)).build().toUri();

        String res = HttpRequest.get(uri.toString()).execute().body();
        logger.info("raw:{}", res);
        byte[] decrypt = facade.decrypt(JSONUtil.toBean(Objects.requireNonNull(res), EncryptorDataWrapper.class));
        logger.info("decryptedData:{}", new String(decrypt));
    }

    @SuppressWarnings("SameParameterValue")
    private void test_post_all_in_one(String url, Map<String, Object> data) {
        EncryptorAutoConfiguration configuration = new EncryptorAutoConfiguration();
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

        String res = HttpRequest.post(url)
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .body(JSONUtil.toJsonStr(encrypt)).execute().body();
        logger.info("raw:{}", res);
        byte[] decrypt = facade.decrypt(JSONUtil.toBean(Objects.requireNonNull(res), EncryptorDataWrapper.class));
        logger.info("decryptedData:{}", new String(decrypt));
    }
}
