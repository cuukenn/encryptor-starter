package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link JweCodec} 与 {@link EncryptorListener} 的接线契约测试：
 * 成功/解密失败/封装失败都必须回调，且失败分类正确。
 *
 * @author changgg
 */
class JweCodecListenerTest {

    private static final String KID = "k1";
    private static final String URI = "/pay/x";

    private static RSAPublicKey publicKey;
    private static ServerKeyStore store;
    private static RecordingListener listener;
    private static JweCodec codec;

    @BeforeAll
    static void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        publicKey = (RSAPublicKey) keyPair.getPublic();
        store = ServerKeyStore.builder()
            .add(KID,
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()),
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()))
            .activeKid(KID)
            .build();
        listener = new RecordingListener();
        codec = new JweCodec(store, Collections.singletonList(new JceCipherSuite()),
            Collections.<String>emptySet(), Collections.<String>emptySet(), listener);
    }

    @BeforeEach
    void resetListener() {
        listener.clear();
    }

    @Test
    void 解密成功回调一次且带上下文() throws Exception {
        long ts = System.currentTimeMillis();
        codec.decryptRequest(clientJwe(ts, "n1", KID), URI, "POST");

        assertEquals(1, listener.decryptSuccesses.size());
        assertEquals(KID, listener.decryptSuccesses.get(0).kid());
        assertEquals("n1", listener.decryptSuccesses.get(0).nonce());
        assertTrue(listener.decryptFailures.isEmpty(), "成功路径不得回调失败");
    }

    @Test
    void 解密失败回调带分类与原因() {
        EncryptorException e = assertThrows(EncryptorException.class,
            () -> codec.decryptRequest(clientJwe(System.currentTimeMillis(), "n1", "nope"), URI, "POST"));
        assertEquals(EncryptorFailure.UNKNOWN_KID, e.failure());

        assertEquals(1, listener.decryptFailures.size(), "失败必须回调且只回调一次");
        assertEquals(EncryptorFailure.UNKNOWN_KID, listener.decryptFailures.get(0), "分类必须透传");
        assertTrue(listener.decryptSuccesses.isEmpty());
    }

    @Test
    void 封装失败回调带分类() {
        byte[] notAesKey = new byte[20];
        assertThrows(EncryptorException.class, () ->
            codec.encryptResponse("x".getBytes(StandardCharsets.UTF_8), notAesKey, URI, "POST",
                System.currentTimeMillis(), "n1"));

        assertEquals(1, listener.encryptFailures.size());
        assertEquals(EncryptorFailure.ENCRYPT_FAILED, listener.encryptFailures.get(0));
        assertTrue(listener.decryptFailures.isEmpty());
    }

    @Test
    void 直接使用JweCodec时监听器异常也不改变结果() {
        EncryptorListener throwing = new EncryptorListener() {
            @Override
            public void onDecryptSuccess(JweContext context) {
                throw new IllegalStateException("boom");
            }

            @Override
            public void onDecryptFailure(EncryptorFailure failure, Throwable cause) {
                throw new IllegalStateException("boom");
            }

            @Override
            public void onEncryptFailure(EncryptorFailure failure, Throwable cause) {
                throw new IllegalStateException("boom");
            }
        };
        JweCodec isolated = new JweCodec(store, Collections.singletonList(new JceCipherSuite()),
            Collections.<String>emptySet(), Collections.<String>emptySet(), throwing);

        JweContext context = assertDoesNotThrow(
            () -> isolated.decryptRequest(clientJwe(System.currentTimeMillis(), "n1", KID), URI, "POST"));
        assertEquals(KID, context.kid());

        EncryptorException decryptError = assertThrows(EncryptorException.class,
            () -> isolated.decryptRequest(clientJwe(System.currentTimeMillis(), "n2", "nope"), URI, "POST"));
        assertEquals(EncryptorFailure.UNKNOWN_KID, decryptError.failure(), "监听器异常不得覆盖原始失败分类");

        EncryptorException encryptError = assertThrows(EncryptorException.class,
            () -> isolated.encryptResponse("x".getBytes(StandardCharsets.UTF_8), new byte[20], URI, "POST",
                System.currentTimeMillis(), "n3"));
        assertEquals(EncryptorFailure.ENCRYPT_FAILED, encryptError.failure(), "监听器异常不得覆盖原始失败分类");
    }

    /** 录制实现：断言回调被触发且分类正确。 */
    private static final class RecordingListener implements EncryptorListener {
        final List<JweContext> decryptSuccesses = new ArrayList<>();
        final List<EncryptorFailure> decryptFailures = new ArrayList<>();
        final List<EncryptorFailure> encryptFailures = new ArrayList<>();

        void clear() {
            decryptSuccesses.clear();
            decryptFailures.clear();
            encryptFailures.clear();
        }

        @Override
        public void onDecryptSuccess(JweContext context) {
            decryptSuccesses.add(context);
        }

        @Override
        public void onDecryptFailure(EncryptorFailure failure, Throwable cause) {
            decryptFailures.add(failure);
        }

        @Override
        public void onEncryptFailure(EncryptorFailure failure, Throwable cause) {
            encryptFailures.add(failure);
        }
    }

    /** 客户端侧按协议构造请求 JWE（与示例前端同一规则）。 */
    private static String clientJwe(long ts, String nonce, String kid) {
        byte[] cek = new byte[32];
        new SecureRandom().nextBytes(cek);
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        try {
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID(kid)
                .customParams(ContextAad.claims(URI, "POST", Direction.REQUEST, ts, nonce))
                .build();
            JWEObject jwe = new JWEObject(header, new Payload("hello".getBytes(StandardCharsets.UTF_8)));
            jwe.encrypt(new RSAEncrypter(publicKey));
            return jwe.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
