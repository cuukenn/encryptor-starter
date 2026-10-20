package io.github.cuukenn.encryptor.reactive.gateway.kit;

import io.github.cuukenn.encryptor.jose.JweContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * {@link GatewayContext} 交换结束后清理敏感数据的契约。
 *
 * @author changgg
 */
class GatewayContextTest {

    @Test
    void destroy清零明文与CEK并断开引用() {
        byte[] plaintext = {1, 2, 3};
        byte[] cek = {4, 5, 6};
        GatewayContext context = new GatewayContext();
        context.setJweContext(new JweContext(plaintext, cek, "kid", "alg", "enc", 1L, "nonce"));
        context.setPlaintextBody(plaintext);

        context.destroy();

        assertArrayEquals(new byte[3], plaintext, "明文体必须被清零");
        assertArrayEquals(new byte[3], cek, "CEK 必须被清零");
        assertNull(context.getJweContext());
        assertNull(context.getPlaintextBody());
    }
}
