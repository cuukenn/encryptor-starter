package io.github.cuukenn.encryptor.kit;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@link DigestKit} 的已知向量与指纹口径测试。
 *
 * @author changgg
 */
class DigestKitTest {

    private static final String ABC_SHA256 =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    @Test
    void sha256Hex匹配标准向量() {
        assertEquals(ABC_SHA256, DigestKit.sha256Hex("abc".getBytes(StandardCharsets.UTF_8)));
        assertEquals(ABC_SHA256, DigestKit.sha256Hex("abc"));
    }

    @Test
    void 指纹取SPKI摘要前6字节() {
        assertEquals(ABC_SHA256.substring(0, 12), DigestKit.fingerprint("abc"));
    }
}
