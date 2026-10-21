package io.github.cuukenn.encryptor.web.kit;

import io.github.cuukenn.encryptor.jose.JweContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * {@link WebContext} 请求结束时清理敏感数据的契约。
 *
 * @author changgg
 */
class WebContextTest {

    @Test
    void clear清零明文与CEK() {
        byte[] plaintext = {1, 2, 3};
        byte[] cek = {4, 5, 6};
        WebContext context = WebContext.current();
        context.setJweContext(new JweContext(plaintext, cek, "kid", "alg", "enc", 1L, "nonce"));
        context.setBodyPlaintext(plaintext);

        WebContext.clear();

        assertArrayEquals(new byte[3], plaintext, "明文体必须被清零");
        assertArrayEquals(new byte[3], cek, "CEK 必须被清零");
    }
}
