package io.github.cuukenn.encryptor.jose;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * {@link JweContext} 的敏感数据清理契约。
 *
 * @author changgg
 */
class JweContextTest {

    @Test
    void destroy清零明文与CEK() {
        byte[] plaintext = {1, 2, 3};
        byte[] cek = {4, 5, 6};
        JweContext context = new JweContext(plaintext, cek, "kid", "alg", "enc", 1L, "nonce");

        context.destroy();

        assertArrayEquals(new byte[3], plaintext, "明文必须被清零");
        assertArrayEquals(new byte[3], cek, "CEK 必须被清零");
    }
}
