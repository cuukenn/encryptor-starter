package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.Collections;

/**
 * 请求体解密路径在认证之前，且原实现一次性把整个 body 读进内存：
 * 单个超大报文就能把堆打爆（open-issues.md P1-13）。过滤器必须按 maxRequestSize 回 413。
 *
 * @author changgg
 */
public class EncryptorRequestBodyFilterTest {
    private static final int MAX_REQUEST_SIZE = 5;

    @AfterEach
    public void tearDown() {
        WebContext.clear();
    }

    private static WebEncryptorConfig config(int maxRequestSize) {
        WebEncryptorConfig config = new WebEncryptorConfig();
        config.setMaxRequestSize(maxRequestSize);
        WebContext.current().setReqEncryptor(true);
        WebContext.current().setConfig(config);
        return config;
    }

    private static EncryptorRequestBodyFilter filter() {
        return new EncryptorRequestBodyFilter(Collections.emptyList());
    }

    /**
     * Content-Length 已知时直接判定：超限回 413，且不能进业务链。
     */
    @Test
    public void test_oversized_body_with_content_length_responds_413_and_skips_chain() throws Exception {
        config(MAX_REQUEST_SIZE);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/test/hello");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(new byte[MAX_REQUEST_SIZE + 1]);

        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean[] chainCalled = {false};
        filter().doFilterInternal(request, response, (req, res) -> chainCalled[0] = true);

        Assertions.assertEquals(413, response.getStatus());
        Assertions.assertFalse(chainCalled[0], "超限报文不能进入业务链");
    }

    /**
     * chunked（没有 Content-Length）时退化为有界读取：读满 limit+1 即可判定超限，回 413。
     */
    @Test
    public void test_oversized_chunked_body_responds_413_and_skips_chain() throws Exception {
        config(MAX_REQUEST_SIZE);

        MockHttpServletRequest raw = new MockHttpServletRequest("POST", "/test/hello");
        raw.setContentType(MediaType.APPLICATION_JSON_VALUE);
        raw.setContent(new byte[MAX_REQUEST_SIZE + 1]);
        // 模拟 chunked：Content-Length 未知
        HttpServletRequest request = new HttpServletRequestWrapper(raw) {
            @Override
            public long getContentLengthLong() {
                return -1;
            }
        };

        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean[] chainCalled = {false};
        filter().doFilterInternal(request, response, (req, res) -> chainCalled[0] = true);

        Assertions.assertEquals(413, response.getStatus());
        Assertions.assertFalse(chainCalled[0], "超限报文不能进入业务链");
    }

    /**
     * 未超限时过滤器仍要把请求交给下游链。
     */
    @Test
    public void test_within_limit_body_still_reaches_chain() throws Exception {
        config(1024);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/test/hello");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(new byte[0]);

        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean[] chainCalled = {false};
        filter().doFilterInternal(request, response, (req, res) -> chainCalled[0] = true);

        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertTrue(chainCalled[0], "未超限时下游链必须被调用");
    }
}
