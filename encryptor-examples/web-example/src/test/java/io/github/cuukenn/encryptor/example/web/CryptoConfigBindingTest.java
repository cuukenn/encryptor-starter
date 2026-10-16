package io.github.cuukenn.encryptor.example.web;

import io.github.cuukenn.encryptor.config.CryptoConfig;
import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

/**
 * P3-7 绑定证据：{@code encryptor.config.web.crypto-config} 的 key 是 <b>uri 正则</b>，
 * 含 {@code .} 时必须用<b>括号写法</b>（YAML 里 {@code "[^/test/secret.*]"}）才能被 Spring Boot
 * 的 Map key 绑定原样保留；裸写 {@code ^/test/secret.*} 会在 {@code .} 处被拆开、静默丢失。
 *
 * <p>本用例不起真实服务（Spring 上下文即可，CI 可跑），只验证配置绑定结果。</p>
 *
 * @author changgg
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class CryptoConfigBindingTest {
    /**
     * yml 里 uri 级覆盖用的正则 key（含 {@code .}）。
     */
    private static final String URI_REGEX_KEY = "^/test/secret.*";
    /**
     * uri 级覆盖配置应绑定的私钥（PKCS8 / Base64），与 application.yml 中一致。
     */
    private static final String URI_LEVEL_PRIVATE_KEY = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7pVGR7T+ontbZWXjSTgUYD04Goh1F1GF/xHPher4TthjY9qnwmf18TwY+0lq62Q7S7EPSKZS4EDteYkoUmsGOoVQterbBMUVvI/SlHalXJNjg8a+0sWcg4rID2pXnSiVy7FcWAJXUrU7FJ+mGS6TEg4zsrn23jwoEOSajnn7weIl6C4t+ZwAOunajkj3pAFCN0/R4eE2BnGKc+Yq4DfU1Z9MTDD9H43PYpvmVsXJDKVZb8u246ig7NESiB8sf7W1eVOG49I2Nuvj2wBQYVXQq+ucE6ygJbkS0ZdciHl6/h2ORGRUQOCgyq+POGXgZs1aSz1M9Ujrnj8NCcev+GeDtAgMBAAECggEAFi4H0sJi1GkWBzHqtJ0RQBNLC0CtShw8/A+6DMxn3EeZb0fUtYJWMpParqFJpS1T8b2IlLZihFEy20it7fqO52+NViTbpkFPLkBnQf8cDZdm5UvcE3Umtf3lwcvcDS839voVnx2pmC52EZrSoROe4bWU+kLzzDclnXMt7IgnBABfm1J2TbwllNqZElfRYIFic9/Axm/6TimxXJOX9rp3bliY52jP3XnBEitrF/X2pAy05pycOJqZ5xDYQtEkkaW/m2lwizBdpm5kSXP4nkP6979yeQhsIjE9tpGFyw3SeVAu4tdKbIEP7s3aAyYX20QLJwhM7R95WE29ExRfWLZIQQKBgQDbMApVUe5FM8ejke8QXFev/OPNukMOWeKIE1EolyzKfUEIJTXE/ryT4ran+BHwvlFCFPW+lFBABBXNtdA94N9o88xhch/7Zha3CSdWf+fZKc9OSxb0bqEX1VjoAK9Zip3Bel50Z99tOHYxQ3C03xuRpigB9v4wduM0rdK+pMiV4QKBgQDbKSMUsL6dPrZI1aCcCDJrOC7etdrv77pEFN7X/0GgVyg408XhAN+sU7Xh+EUE9rJXSVXBkWX9YGMCl18c7QVqpG4p+D9E4XbtFahnEfB7LC8b25cPDPvO14IKlxxii0J9jehn2zToyQJ2viSsP80TuRGIUTy15XGJ6Q8gfaHUjQKBgQCwzmq3cjSSi/cxQamm9+Yf5w3XSLWIoQbznylrZa7S1ACeUm2yL43seQfALIJEQTEI7iFhDwBA80qnOk71ayyr22V1AXs87pfKI88gnmJmMaywyi+FEqxNrmJeGxdXUlJ43H3Oxm9bCh2FFZKXxBTYA0DofNWEQJJ8Tu7dq8zF4QKBgQCVYvUGpXNIu/aErxlLQksbyrAoHs2dv0q4HYHIubWCFebU1YWMWYwdavIPlat2NrJZzSMnTnS2wXy7x3KNxQJsLqjo8s4tpYHrGVgw6YmCbBuwYX4WRENgOoXpshcnFMW9z30bTdBC3MFRL0rQHq0rRHsu8DDxy/QYjURCYWBuAQKBgAqy6NhGLpslMAOAjFKwSME9rFtL7SjzaKziHgvYDaNGjUPZeOv7CP7PieWeCdECuuUh4nm1pEghaMPD+VCinp/lMhhbecWqE2deIRoPdPWzqAn5mUm9aVrox17XM1Bme2wFs3hWVmWWpE/fgpuF/zmad1fBrtMldr83ZB2ii+qE";
    /**
     * uri 级覆盖配置应绑定的公钥（X509 / Base64），与 application.yml 中一致。
     */
    private static final String URI_LEVEL_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu6VRke0/qJ7W2Vl40k4FGA9OBqIdRdRhf8Rz4Xq+E7YY2Pap8Jn9fE8GPtJautkO0uxD0imUuBA7XmJKFJrBjqFULXq2wTFFbyP0pR2pVyTY4PGvtLFnIOKyA9qV50olcuxXFgCV1K1OxSfphkukxIOM7K59t48KBDkmo55+8HiJeguLfmcADrp2o5I96QBQjdP0eHhNgZxinPmKuA31NWfTEww/R+Nz2Kb5lbFyQylWW/LtuOooOzREogfLH+1tXlThuPSNjbr49sAUGFV0KvrnBOsoCW5EtGXXIh5ev4djkRkVEDgoMqvjzhl4GbNWks9TPVI654/DQnHr/hng7QIDAQAB";

    @Autowired
    private WebEncryptorConfig webEncryptorConfig;
    @Autowired
    private EncryptorConfig encryptorConfig;

    @Test
    public void uriLevelCryptoConfigWithDotInRegexKeyShouldBind() {
        Map<String, CryptoConfig> cryptoConfig = webEncryptorConfig.getCryptoConfig();
        Assertions.assertNotNull(cryptoConfig, "web.crypto-config 不应为 null");
        Assertions.assertTrue(cryptoConfig.containsKey(URI_REGEX_KEY),
                "crypto-config 应原样包含含 `.` 的正则 key [" + URI_REGEX_KEY + "]，实际 keys=" + cryptoConfig.keySet());
        CryptoConfig uriLevel = cryptoConfig.get(URI_REGEX_KEY);
        Assertions.assertNotNull(uriLevel, "命中 key 的 CryptoConfig 不应为 null");
        // 必须等于 yml 里写的那对覆盖密钥，而不是全局默认那对
        Assertions.assertEquals(URI_LEVEL_PRIVATE_KEY, uriLevel.getPrivateKey(), "uri 级 private-key 应为覆盖配置那对");
        Assertions.assertEquals(URI_LEVEL_PUBLIC_KEY, uriLevel.getPublicKey(), "uri 级 public-key 应为覆盖配置那对");
        // 与全局默认做反向对照，进一步证明"覆盖"确实覆盖了
        String globalPublicKey = encryptorConfig.getCryptoConfig().getPublicKey();
        Assertions.assertNotEquals(globalPublicKey, uriLevel.getPublicKey(), "uri 级公钥不应等于全局默认公钥");
    }

    @Test
    public void globalCryptoConfigShouldRemainUnchanged() {
        // 全局（encryptor.config.crypto-config）保持原样，是 /test/hello 等未命中端点用的那套
        String globalPublicKey = encryptorConfig.getCryptoConfig().getPublicKey();
        Assertions.assertNotNull(globalPublicKey, "全局默认公钥不应为空");
        Assertions.assertNotEquals(URI_LEVEL_PUBLIC_KEY, globalPublicKey, "全局默认公钥不应被 uri 级覆盖污染");
    }
}
