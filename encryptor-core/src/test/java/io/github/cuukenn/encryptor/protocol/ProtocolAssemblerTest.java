package io.github.cuukenn.encryptor.protocol;

import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.jose.KeyType;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 两侧自动装配共用的协议栈组装入口。
 *
 * @author changgg
 */
class ProtocolAssemblerTest {

    @Test
    void 按配置组装密钥白名单与运行期旁路() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        DefaultProtocol.KeyMaterial key = new DefaultProtocol.KeyMaterial(
            "k1",
            KeyType.RSA,
            Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()),
            Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        Set<String> algs = Collections.singleton("RSA-OAEP-256");
        Set<String> encs = Collections.singleton("A256GCM");

        DefaultProtocol protocol = ProtocolAssembler.assemble(
            Collections.singletonList(key),
            "k1",
            algs,
            encs,
            60_000L,
            120_000L,
            32,
            null,
            EncryptorListener.NONE,
            true,
            false);

        assertEquals("k1", protocol.keys().activeKid());
        assertEquals(new LinkedHashSet<>(algs), protocol.allowedAlgs());
        assertEquals(new LinkedHashSet<>(encs), protocol.allowedEncs());
        assertEquals(60_000L, protocol.ttlMillis());
        assertTrue(protocol.runtime().bypassRequest());
        assertFalse(protocol.runtime().bypassResponse());
    }
}
