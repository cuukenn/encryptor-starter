package io.github.cuukenn.encryptor.jose;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

    @Test
    void destroy之后cek与plaintext必须拒绝访问() {
        JweContext context = new JweContext(new byte[]{1}, new byte[]{2}, "kid", "alg", "enc", 1L, "nonce");
        context.destroy();

        // 全零数组是合法 AES 密钥：静默返回会产出客户端必然解不开的报文且服务端无告警
        assertEquals("JweContext 已销毁（cek 已清零），不能再用于响应加密",
            assertThrows(IllegalStateException.class, context::cek).getMessage());
        assertEquals("JweContext 已销毁（plaintext 已清零）",
            assertThrows(IllegalStateException.class, context::plaintext).getMessage());
        // 元数据不受影响（审计/日志还要读）
        assertEquals("kid", context.kid());
    }
}
