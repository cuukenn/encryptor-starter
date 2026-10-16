package io.github.cuukenn.encryptor.web.filter;

import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

/**
 * black-res-content-type 必须等"响应产生之后"再判定：
 * 过滤器刚进入时响应还没有 Content-Type（handler 还没跑），那时判定等于永远不生效。
 *
 * @author changgg
 */
public class EncryptorResponseFilterTest {
    private static final String BLACK_CONTENT_TYPE = "application/octet-stream";
    private static final byte[] BODY = "plain-body".getBytes(StandardCharsets.UTF_8);

    @AfterEach
    public void clearContext() {
        WebContext.clear();
    }

    private static WebEncryptorConfig config(String... blackResContentType) {
        WebEncryptorConfig config = new WebEncryptorConfig();
        config.setBlackResContentType(Arrays.asList(blackResContentType));
        return config;
    }

    private static void setUpContext(WebEncryptorConfig config, EncryptorFacade facade) {
        WebContext.current().setEncryptor(true);
        WebContext.current().setReqEncryptor(true);
        WebContext.current().setConfig(config);
        WebContext.current().setEncryptorFacade(facade);
    }

    /**
     * @param result 非 null 时返回固定结果；null 表示"一旦被调用就失败"（黑名单响应不该走加密）
     */
    private static EncryptorFacade facade(EncryptorDataWrapper result) {
        return new EncryptorFacade(null, null, null, null) {
            @Override
            public EncryptorDataWrapper encrypt(byte[] data, String key) {
                if (result == null) {
                    throw new AssertionError("black-res-content-type 命中的响应不允许被加密");
                }
                return result;
            }
        };
    }

    @Test
    public void test_blacklisted_response_content_type_is_not_encrypted() throws Exception {
        setUpContext(config(BLACK_CONTENT_TYPE), facade(null));
        EncryptorResponseFilter filter = new EncryptorResponseFilter(Collections.emptyList());
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/test/hello");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilterInternal(request, response, (req, res) -> {
            res.setContentType(BLACK_CONTENT_TYPE);
            res.getOutputStream().write(BODY);
        });

        // 响应体必须原样放行，且不能是空响应
        Assertions.assertEquals("plain-body", new String(response.getContentAsByteArray(), StandardCharsets.UTF_8));
    }

    @Test
    public void test_encryptable_response_content_type_is_still_encrypted() throws Exception {
        EncryptorDataWrapper wrapper = new EncryptorDataWrapper("nonce", 1L, "sig", "key", "data");
        setUpContext(config(BLACK_CONTENT_TYPE), facade(wrapper));
        EncryptorResponseFilter filter = new EncryptorResponseFilter(Collections.emptyList());
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/test/hello");
        // 响应加密的前提：这次请求协商出过 key（加密请求里由解密过滤器写入 x-key 属性）
        request.setAttribute(CoreEncryptorConstant.KEY, "key");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilterInternal(request, response, (req, res) -> {
            res.setContentType("application/json");
            res.getOutputStream().write(BODY);
        });

        Assertions.assertEquals(JSONUtil.toJsonStr(wrapper),
                new String(response.getContentAsByteArray(), StandardCharsets.UTF_8));
    }

    /**
     * 请求方向开着加密、但这次请求没有协商出 key（例如明文 GET：没有 data/key 参数，就没有 {@code x-key} attribute）：
     * 此时响应不能尝试加密 —— key 为 null 时 RSA 解不开，客户端会拿到 500。
     */
    @Test
    public void test_response_without_negotiated_key_is_passed_through() throws Exception {
        setUpContext(config(), facade(null));
        EncryptorResponseFilter filter = new EncryptorResponseFilter(Collections.emptyList());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/test/hello");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilterInternal(request, response, (req, res) -> {
            res.setContentType("application/json");
            res.getOutputStream().write(BODY);
        });

        Assertions.assertEquals("plain-body", new String(response.getContentAsByteArray(), StandardCharsets.UTF_8));
        Assertions.assertEquals(200, response.getStatus());
    }
}
