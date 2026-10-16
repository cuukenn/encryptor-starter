package io.github.cuukenn.encryptor;

import cn.hutool.core.util.IdUtil;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.configuration.EncryptorAutoConfiguration;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.facade.IEncryptorFacadeFactory;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * @author changgg
 */
public class HttpTest {
    private static final Logger logger = LoggerFactory.getLogger(HttpTest.class);
    private static final String privateKey = "MIICWAIBAAKBgGETAZi4hJ6ZxQWhHvM22BRivGOg/PzFo9+KNjAPwpzGkHkklQ1meB9kWYXo10VVDE6mXpzHFfPq1Lww1sRRAZs2oMib+hUqx67Mai93oEcQrzt31e4M6Ulscfnz9XwG9/TAoWoIdGU8S5ZNUihfTPkbUAJ7KQ60FpAgHF8mb/ljAgMBAAECf3rbkym2XiJcev6k7Ibk4pTqYYO2PHmtqblBM1Ognq3MoQyxP/O1vFH+r07LYahd+zWPWi8RyLbsflGvfiD4ZQ59AbFz/dJ2GtqkualXUC1s813nf8/PQ1CIqxg+9ZmFk2z6qLrqJGW8liiho/GUdECwLfho01iQfXX74N/xW8ECQQCgAJylo12dDTm4ICkpTPqCkP1qnIbtcnxJYtuUTKzNY8oqvOmE1AEvqtJav6xQyueYzl24gLoCoYcTIgep/f3ZAkEAm1EEF8XoLvigvCCygB+IBVNYPYcPLNZO4LPB/zi74byBD4EtGQ+NO0IIhB0XiXP6e9gJbkaMe9u7PnzS4vofmwJAHA3faX+Kc3YVL76b2P0BU5FejaniUpHnTurBe3AyQFUF5pZ3D24owxXdikHfUc8x6m4MqsQPWVS/HVCzLVA2iQJAVA7jxS4B/DHpZAfaM4ddKWyzDBGlf+G4rNn8u3FsFb7cppSF4NNO32xciYvpKiYPwajpabpa28nPLAGIbPlr0wJAItIt4P0DE5+27ogDF5+XFWK0M+GddL+0D6VnHrwnvhmcORiFsJyBuxc+WkEi9JLZwff91+aLgLEa4r+BgxBIVg==";
    private static final String publicKey = "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGETAZi4hJ6ZxQWhHvM22BRivGOg/PzFo9+KNjAPwpzGkHkklQ1meB9kWYXo10VVDE6mXpzHFfPq1Lww1sRRAZs2oMib+hUqx67Mai93oEcQrzt31e4M6Ulscfnz9XwG9/TAoWoIdGU8S5ZNUihfTPkbUAJ7KQ60FpAgHF8mb/ljAgMBAAE=";
    /**
     * uri 级覆盖（{@code ^/test/secret.*}）对应的一对密钥，与 application.yml 中
     * {@code encryptor.config.web.crypto-config} 的覆盖配置一致。
     */
    private static final String uriLevelPrivateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7pVGR7T+ontbZWXjSTgUYD04Goh1F1GF/xHPher4TthjY9qnwmf18TwY+0lq62Q7S7EPSKZS4EDteYkoUmsGOoVQterbBMUVvI/SlHalXJNjg8a+0sWcg4rID2pXnSiVy7FcWAJXUrU7FJ+mGS6TEg4zsrn23jwoEOSajnn7weIl6C4t+ZwAOunajkj3pAFCN0/R4eE2BnGKc+Yq4DfU1Z9MTDD9H43PYpvmVsXJDKVZb8u246ig7NESiB8sf7W1eVOG49I2Nuvj2wBQYVXQq+ucE6ygJbkS0ZdciHl6/h2ORGRUQOCgyq+POGXgZs1aSz1M9Ujrnj8NCcev+GeDtAgMBAAECggEAFi4H0sJi1GkWBzHqtJ0RQBNLC0CtShw8/A+6DMxn3EeZb0fUtYJWMpParqFJpS1T8b2IlLZihFEy20it7fqO52+NViTbpkFPLkBnQf8cDZdm5UvcE3Umtf3lwcvcDS839voVnx2pmC52EZrSoROe4bWU+kLzzDclnXMt7IgnBABfm1J2TbwllNqZElfRYIFic9/Axm/6TimxXJOX9rp3bliY52jP3XnBEitrF/X2pAy05pycOJqZ5xDYQtEkkaW/m2lwizBdpm5kSXP4nkP6979yeQhsIjE9tpGFyw3SeVAu4tdKbIEP7s3aAyYX20QLJwhM7R95WE29ExRfWLZIQQKBgQDbMApVUe5FM8ejke8QXFev/OPNukMOWeKIE1EolyzKfUEIJTXE/ryT4ran+BHwvlFCFPW+lFBABBXNtdA94N9o88xhch/7Zha3CSdWf+fZKc9OSxb0bqEX1VjoAK9Zip3Bel50Z99tOHYxQ3C03xuRpigB9v4wduM0rdK+pMiV4QKBgQDbKSMUsL6dPrZI1aCcCDJrOC7etdrv77pEFN7X/0GgVyg408XhAN+sU7Xh+EUE9rJXSVXBkWX9YGMCl18c7QVqpG4p+D9E4XbtFahnEfB7LC8b25cPDPvO14IKlxxii0J9jehn2zToyQJ2viSsP80TuRGIUTy15XGJ6Q8gfaHUjQKBgQCwzmq3cjSSi/cxQamm9+Yf5w3XSLWIoQbznylrZa7S1ACeUm2yL43seQfALIJEQTEI7iFhDwBA80qnOk71ayyr22V1AXs87pfKI88gnmJmMaywyi+FEqxNrmJeGxdXUlJ43H3Oxm9bCh2FFZKXxBTYA0DofNWEQJJ8Tu7dq8zF4QKBgQCVYvUGpXNIu/aErxlLQksbyrAoHs2dv0q4HYHIubWCFebU1YWMWYwdavIPlat2NrJZzSMnTnS2wXy7x3KNxQJsLqjo8s4tpYHrGVgw6YmCbBuwYX4WRENgOoXpshcnFMW9z30bTdBC3MFRL0rQHq0rRHsu8DDxy/QYjURCYWBuAQKBgAqy6NhGLpslMAOAjFKwSME9rFtL7SjzaKziHgvYDaNGjUPZeOv7CP7PieWeCdECuuUh4nm1pEghaMPD+VCinp/lMhhbecWqE2deIRoPdPWzqAn5mUm9aVrox17XM1Bme2wFs3hWVmWWpE/fgpuF/zmad1fBrtMldr83ZB2ii+qE";
    private static final String uriLevelPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu6VRke0/qJ7W2Vl40k4FGA9OBqIdRdRhf8Rz4Xq+E7YY2Pap8Jn9fE8GPtJautkO0uxD0imUuBA7XmJKFJrBjqFULXq2wTFFbyP0pR2pVyTY4PGvtLFnIOKyA9qV50olcuxXFgCV1K1OxSfphkukxIOM7K59t48KBDkmo55+8HiJeguLfmcADrp2o5I96QBQjdP0eHhNgZxinPmKuA31NWfTEww/R+Nz2Kb5lbFyQylWW/LtuOooOzREogfLH+1tXlThuPSNjbr49sAUGFV0KvrnBOsoCW5EtGXXIh5ev4djkRkVEDgoMqvjzhl4GbNWks9TPVI654/DQnHr/hng7QIDAQAB";

    @Test
    public void test_get() {
        String body = test_get_all_in_one("http://127.0.0.1:8081/test/hello", Collections.singletonMap("name", "小明"));
        // GET /test/hello 返回 "Hello, " + name
        Assertions.assertTrue(body.contains("Hello"), "响应应包含 Hello，实际为: " + body);
        Assertions.assertTrue(body.contains("小明"), "响应应回显请求参数 name=小明，实际为: " + body);
    }

    /**
     * 正向：{@code /test/secret} 命中 uri 级覆盖正则 {@code ^/test/secret.*}，
     * 必须用覆盖那对公钥（yml 里 {@code encryptor.config.web.crypto-config}）构造请求才能被服务端解开。
     */
    @Test
    public void test_get_uri_level_crypto_config() {
        String body = test_get_all_in_one("http://127.0.0.1:8081/test/secret",
                Collections.singletonMap("name", "小明"), uriLevelPublicKey, uriLevelPrivateKey);
        Assertions.assertTrue(body.contains("Secret"), "响应应包含 Secret，实际为: " + body);
        Assertions.assertTrue(body.contains("小明"), "响应应回显请求参数 name=小明，实际为: " + body);
    }

    /**
     * 反向对照：用全局默认那对公钥请求被 uri 级覆盖的 {@code /test/secret}，
     * 服务端会用覆盖私钥去解 {@code key} → 解不开 → 400（证明"命中的确实是覆盖配置那套密钥"）。
     */
    @Test
    public void test_get_uri_level_crypto_config_wrong_key_rejected() {
        EncryptorFacade globalFacade = buildFacade(publicKey, privateKey);
        EncryptorDataWrapper encrypt = buildGetRequest(Collections.singletonMap("name", "小明"), globalFacade);
        HttpResponse response = sendGet("http://127.0.0.1:8081/test/secret", encrypt);
        logger.info("wrong-key status: {}, body: {}", response.getStatus(), response.body());
        Assertions.assertEquals(400, response.getStatus(),
                "用全局密钥请求被 uri 级覆盖的端点应被拒（400），实际: " + response.getStatus());
    }

    @Test
    public void test_post() {
        String body = test_post_all_in_one("http://127.0.0.1:8081/test/hello", Collections.singletonMap("name", "小明"));
        // POST /test/hello(JSON) 返回 "Hello, " + data（data 是 {name=小明}）
        Assertions.assertTrue(body.contains("Hello"), "响应应包含 Hello，实际为: " + body);
        Assertions.assertTrue(body.contains("小明"), "响应应回显请求体中的 name=小明，实际为: " + body);
    }

    @SuppressWarnings("SameParameterValue")
    private String test_get_all_in_one(String url, Map<String, Object> params) {
        return test_get_all_in_one(url, params, publicKey, privateKey);
    }

    /**
     * 用指定的服务端密钥对发一次 GET 并解出明文。
     * 传入的密钥对决定了服务端是否解得开：命中 uri 级覆盖的端点必须传覆盖那对。
     */
    private String test_get_all_in_one(String url, Map<String, Object> params, String serverPublicKey, String serverPrivateKey) {
        EncryptorFacade facade = buildFacade(serverPublicKey, serverPrivateKey);
        EncryptorDataWrapper encrypt = buildGetRequest(params, facade);
        HttpResponse response = sendGet(url, encrypt);
        Assertions.assertEquals(200, response.getStatus(), "GET " + url + " 应返回 200");
        return decryptResponse(response, facade);
    }

    private EncryptorFacade buildFacade(String serverPublicKey, String serverPrivateKey) {
        EncryptorAutoConfiguration configuration = new EncryptorAutoConfiguration();
        IEncryptorFacadeFactory<CryptoConfig> facadeFactory = configuration.encryptorFacadeFactory(Collections.emptyList());
        CryptoConfig cryptoConfig = new CryptoConfig();
        cryptoConfig.setPublicKey(serverPublicKey);
        cryptoConfig.setPrivateKey(serverPrivateKey);
        return facadeFactory.apply(cryptoConfig);
    }

    private EncryptorDataWrapper buildGetRequest(Map<String, Object> params, EncryptorFacade facade) {
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
        return encrypt;
    }

    private HttpResponse sendGet(String url, EncryptorDataWrapper encrypt) {
        // hutool 的 form()（以及 UriComponentsBuilder 默认行为）不会把 base64 里的 '+' 编码成 %2B，
        // 服务端 getParameterMap() 会把它解成空格、密文被改坏 -> 400。这里自己严格 URL 编码。
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
        return HttpRequest.get(fullUrl.toString()).execute();
    }

    private String decryptResponse(HttpResponse response, EncryptorFacade facade) {
        String res = response.body();
        logger.info("raw:{}", res);
        byte[] decrypt = facade.decrypt(JSONUtil.toBean(Objects.requireNonNull(res), EncryptorDataWrapper.class));
        String plaintext = new String(decrypt);
        logger.info("decryptedData:{}", plaintext);
        return plaintext;
    }

    @SuppressWarnings("SameParameterValue")
    private String test_post_all_in_one(String url, Map<String, Object> data) {
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

        HttpResponse response = HttpRequest.post(url)
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .body(JSONUtil.toJsonStr(encrypt)).execute();
        Assertions.assertEquals(200, response.getStatus(), "POST " + url + " 应返回 200");
        String res = response.body();
        logger.info("raw:{}", res);
        byte[] decrypt = facade.decrypt(JSONUtil.toBean(Objects.requireNonNull(res), EncryptorDataWrapper.class));
        String plaintext = new String(decrypt);
        logger.info("decryptedData:{}", plaintext);
        return plaintext;
    }
}
