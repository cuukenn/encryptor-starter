package io.github.cuukenn.encryptor.jose;

import io.github.cuukenn.encryptor.kit.DigestKit;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JWKS 文档在 core 里统一生成，servlet/gateway 两侧只负责写响应。
 *
 * @author changgg
 */
class JwksDocumentTest {

    @Test
    void body包含公钥与activeKid且etag为带引号的sha256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        ServerKeyStore keys = ServerKeyStore.builder()
            .add("k1", privateKey, publicKey)
            .activeKid("k1")
            .build();

        JwksDocument document = new JwksDocument(keys);

        assertTrue(document.body().contains("\"keys\""));
        assertTrue(document.body().contains("\"activeKid\":\"k1\""));
        assertTrue(document.body().contains("\"k1\""));
        assertEquals("\"" + DigestKit.sha256Hex(document.body()) + "\"", document.etag());
    }
}
