package io.github.cuukenn.encryptor.jose;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link JceCipherSuite} 契约测试：RSA-OAEP-256 封装 + AES-GCM 内容加密。
 *
 * @author changgg
 */
class JceCipherSuiteTest {

    private final JceCipherSuite suite = new JceCipherSuite();

    @Test
    void 声明支持的算法与加密方法() {
        assertEquals(Collections.singleton("RSA-OAEP-256"), suite.algorithms());
        assertEquals(new HashSet<>(Arrays.asList("A128GCM", "A192GCM", "A256GCM")), suite.encryptionMethods());
        assertEquals(16, suite.keyLength("A128GCM"));
        assertEquals(24, suite.keyLength("A192GCM"));
        assertEquals(32, suite.keyLength("A256GCM"));
    }

    @Test
    void 未知加密方法一律拒绝() {
        assertThrows(EncryptorException.class, () -> suite.keyLength("A128CBC-HS256"));
        assertThrows(EncryptorException.class,
            () -> suite.aeadEncrypt("A128CBC-HS256", new byte[16], new byte[12], "x".getBytes(), new byte[0]));
        assertThrows(EncryptorException.class,
            () -> suite.aeadDecrypt("SM4-GCM", new byte[16], new byte[12], new byte[4], new byte[16], new byte[0]));
    }

    @Test
    void CEK解封往返() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        ServerKeyStore store = ServerKeyStore.builder()
            .add("k1", base64(keyPair.getPrivate().getEncoded()), base64(keyPair.getPublic().getEncoded()))
            .activeKid("k1")
            .build();

        byte[] cek = new byte[32];
        new SecureRandom().nextBytes(cek);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), new OAEPParameterSpec("SHA-256", "MGF1",
            MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        byte[] wrapped = cipher.doFinal(cek);

        assertArrayEquals(cek, suite.unwrapCek(store, "k1", "RSA-OAEP-256", wrapped));
    }

    @Test
    void AEAD往返且篡改必然失败() throws Exception {
        byte[] cek = new byte[32];
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(cek);
        new SecureRandom().nextBytes(iv);
        byte[] aad = "protected".getBytes("US-ASCII");
        byte[] plaintext = "hello 报文层".getBytes("UTF-8");

        byte[] packed = suite.aeadEncrypt("A256GCM", cek, iv, plaintext, aad);
        assertEquals(plaintext.length + 16, packed.length, "GCM 输出 = 密文 + 16 字节 tag");

        byte[] cipherText = Arrays.copyOf(packed, packed.length - 16);
        byte[] authTag = Arrays.copyOfRange(packed, packed.length - 16, packed.length);
        assertArrayEquals(plaintext, suite.aeadDecrypt("A256GCM", cek, iv, cipherText, authTag, aad));

        byte[] tamperedTag = authTag.clone();
        tamperedTag[0] ^= 1;
        assertThrows(Exception.class, () -> suite.aeadDecrypt("A256GCM", cek, iv, cipherText, tamperedTag, aad),
            "篡改 tag 必须失败");

        byte[] tamperedAad = "protecteD".getBytes("US-ASCII");
        assertThrows(Exception.class, () -> suite.aeadDecrypt("A256GCM", cek, iv, cipherText, authTag, tamperedAad),
            "篡改 AAD 必须失败");
    }

    private static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
