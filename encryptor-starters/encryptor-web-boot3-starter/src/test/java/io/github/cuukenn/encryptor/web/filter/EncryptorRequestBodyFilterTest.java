package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * v2 请求体视图过滤器：只装 WebContext.bodyPlaintext。
 *
 * @author changgg
 */
class EncryptorRequestBodyFilterTest {
    private final EncryptorRequestBodyFilter filter = new EncryptorRequestBodyFilter();
    private final MockHttpServletResponse response = new MockHttpServletResponse();

    @AfterEach
    void tearDown() {
        WebContext.clear();
    }

    @Test
    void 解密后的请求体以明文流交付且长度正确() throws Exception {
        byte[] plaintext = "{\"name\":\"alice\"}".getBytes(StandardCharsets.UTF_8);
        WebContext ctx = WebContext.current();
        ctx.setReqEncryptor(true);
        ctx.setBodyPlaintext(plaintext);
        FilterChain chain = (request, resp) -> {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[256];
            // 流只能取一次：每轮 getInputStream() 会新建流导致死循环
            java.io.InputStream stream = request.getInputStream();
            int read;
            while ((read = stream.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            assertThat(out.toByteArray()).isEqualTo(plaintext);
            assertThat(request.getContentLength()).isEqualTo(plaintext.length);
            assertThat(request.getContentLengthLong()).isEqualTo(plaintext.length);
            // getReader 走同一份明文
            BufferedReader reader = new BufferedReader(new InputStreamReader(request.getInputStream(), StandardCharsets.UTF_8));
            assertThat(reader.readLine()).isEqualTo("{\"name\":\"alice\"}");
        };
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/j");
        filter.doFilter(request, response, chain);
    }

    @Test
    void 无密文请求原样透传() throws Exception {
        AtomicReference<ServletRequest> seen = new AtomicReference<>();
        FilterChain chain = (request, resp) -> seen.set(request);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/plain");
        filter.doFilter(request, response, chain);
        assertThat(seen.get()).isSameAs(request);
    }
}
