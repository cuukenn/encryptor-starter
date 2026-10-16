package io.github.cuukenn.encryptor.web.filter;

import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.digest.MD5;
import cn.hutool.crypto.symmetric.AES;
import io.github.cuukenn.encryptor.core.digester.HtlDigester;
import io.github.cuukenn.encryptor.core.encoder.Base64Encoder;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.core.encryptor.HtlASymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.encryptor.HtlSymmetricCryptoEncryptor;
import io.github.cuukenn.encryptor.core.signer.DigestWithEncryptSigner;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.kit.EncryptorKit;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

/**
 * @author changgg
 */
public class EncryptorRequestParameterFilterTest {
    private static final byte[] KEY = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8);
    private static final String PARAMS = "{\"mode\":\"CBC\",\"padding\":\"PKCS5Padding\","
            + "\"key\":\"MDEyMzQ1Njc4OWFiY2RlZg==\",\"iv\":\"abcdefghijklmnop\"}";

    @Test
    public void test_parse_form_data_without_equal_sign() {
        // 原实现会对 "broken" 调用 substring(0, -1) 抛 StringIndexOutOfBoundsException
        Map<Object, Object> parameters = EncryptorRequestParameterFilter.parseFormData("a=1&broken");
        Assertions.assertEquals("1", parameters.get("a"));
        Assertions.assertEquals("", parameters.get("broken"));
    }

    @Test
    public void test_parse_form_data_duplicated_key_keeps_first_value() {
        // 原实现 Collectors.toMap 没有合并函数，重复 key 会抛 IllegalStateException
        Map<Object, Object> parameters = EncryptorRequestParameterFilter.parseFormData("a=1&a=2");
        Assertions.assertEquals("1", parameters.get("a"));
    }

    /**
     * 包装后的请求必须让 getParameter / getParameterValues / getParameterMap 三个视图都拿到明文。
     *
     * <p>只覆写后两个的话，{@code request.getParameter("field")} 与 {@code getParameterMap()} 会回落到
     * 被包装的原始请求，拿到的是密文（或直接是 null）——同一个请求里出现两个数据视图。</p>
     */
    @Test
    public void test_wrapped_request_exposes_plaintext_from_all_parameter_accessors() throws Exception {
        AES aes = new AES("CBC", "PKCS5Padding", KEY, IV);
        RSA rsa = new RSA();
        String negotiatedKey = rsa.encryptBase64(PARAMS, KeyType.PublicKey);

        Function<String, EncryptorEncoder> encryptorEncoder = ignored -> new EncryptorEncoder(new HtlSymmetricCryptoEncryptor(aes), new Base64Encoder());
        Function<String, SignerEncoder> signerEncoder = ignored -> new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()),
                new HtlSymmetricCryptoEncryptor(aes)), new Base64Encoder());
        EncryptorFacade facade = new EncryptorFacade(
                new EncryptorEncoder(new HtlASymmetricCryptoEncryptor(rsa), new Base64Encoder()),
                encryptorEncoder, signerEncoder, Collections.emptyList());

        EncryptorDataWrapper wrapper = EncryptorKit.encrypt(encryptorEncoder.apply(PARAMS), signerEncoder.apply(PARAMS),
                "{\"field\":\"plain\"}".getBytes(StandardCharsets.UTF_8), negotiatedKey);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/test/hello");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setParameter("nonce", wrapper.getNonce());
        request.setParameter("timestamp", String.valueOf(wrapper.getTimestamp()));
        request.setParameter("signature", wrapper.getSignature());
        request.setParameter("key", wrapper.getKey());
        request.setParameter("data", wrapper.getData());

        WebContext.current().setReqEncryptor(true);
        WebContext.current().setEncryptorFacade(facade);
        WebContext.current().setConfig(new WebEncryptorConfig());

        final HttpServletRequest[] captured = new HttpServletRequest[1];
        try {
            new EncryptorRequestParameterFilter().doFilterInternal(request, new MockHttpServletResponse(),
                    (req, res) -> captured[0] = (HttpServletRequest) req);
        } finally {
            WebContext.clear();
        }

        HttpServletRequest wrapped = captured[0];
        Assertions.assertEquals("plain", wrapped.getParameter("field"));
        Assertions.assertEquals("plain", wrapped.getParameterValues("field")[0]);
        Assertions.assertEquals("plain", wrapped.getParameterMap().get("field")[0]);
    }

    /**
     * 解不开的报文（篡改 signature）必须收敛成"报文非法"：回 4xx 且不进业务链，
     * 而不是把 hutool 的 CryptoException 抛成 500。
     */
    @Test
    public void test_undecryptable_payload_responds_with_failure_status_and_skips_chain() throws Exception {
        AES aes = new AES("CBC", "PKCS5Padding", KEY, IV);
        RSA rsa = new RSA();
        String negotiatedKey = rsa.encryptBase64(PARAMS, KeyType.PublicKey);

        Function<String, EncryptorEncoder> encryptorEncoder = ignored -> new EncryptorEncoder(new HtlSymmetricCryptoEncryptor(aes), new Base64Encoder());
        Function<String, SignerEncoder> signerEncoder = ignored -> new SignerEncoder(new DigestWithEncryptSigner(new HtlDigester(new MD5()),
                new HtlSymmetricCryptoEncryptor(aes)), new Base64Encoder());
        EncryptorFacade facade = new EncryptorFacade(
                new EncryptorEncoder(new HtlASymmetricCryptoEncryptor(rsa), new Base64Encoder()),
                encryptorEncoder, signerEncoder, Collections.emptyList());

        EncryptorDataWrapper wrapper = EncryptorKit.encrypt(encryptorEncoder.apply(PARAMS), signerEncoder.apply(PARAMS),
                "{\"field\":\"plain\"}".getBytes(StandardCharsets.UTF_8), negotiatedKey);
        // 篡改签名：3 字节，不是 AES 分组长度
        wrapper.setSignature(java.util.Base64.getEncoder().encodeToString(new byte[]{1, 2, 3}));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/test/hello");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setParameter("nonce", wrapper.getNonce());
        request.setParameter("timestamp", String.valueOf(wrapper.getTimestamp()));
        request.setParameter("signature", wrapper.getSignature());
        request.setParameter("key", wrapper.getKey());
        request.setParameter("data", wrapper.getData());

        WebContext.current().setReqEncryptor(true);
        WebContext.current().setEncryptorFacade(facade);
        WebContext.current().setConfig(new WebEncryptorConfig());

        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean[] chainCalled = {false};
        try {
            new EncryptorRequestParameterFilter().doFilterInternal(request, response,
                    (req, res) -> chainCalled[0] = true);
        } finally {
            WebContext.clear();
        }

        Assertions.assertEquals(400, response.getStatus());
        Assertions.assertFalse(chainCalled[0], "报文非法时不能进业务链");
    }
}
