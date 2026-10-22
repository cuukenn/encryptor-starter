package io.github.cuukenn.encryptor.protocol;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.exception.EncryptorFailure;
import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.Direction;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.jose.KeyType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@link DefaultProtocol#openRequest} 的失败面契约：防重放是请求生命周期的一部分，
 * REPLAY/EXPIRED 必须进入监听器失败回调，且不能先记一次"解密成功"。
 *
 * @author changgg
 */
class DefaultProtocolOpenRequestTest {

    private static final String KID = "k1";
    private static final String URI = "/pay/x";

    private static KeyPair keyPair;
    private static DefaultProtocol protocol;
    private static RecordingListener listener;

    @BeforeAll
    static void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        listener = new RecordingListener();
        protocol = DefaultProtocol.builder()
            .key(new DefaultProtocol.KeyMaterial(KID, KeyType.RSA,
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()),
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())))
            .listener(listener)
            .build();
    }

    @BeforeEach
    void resetListener() {
        listener.clear();
    }

    @Test
    void 重放不回调成功且回调REPLAY失败() throws Exception {
        String compact = seal(newNonce(), System.currentTimeMillis());
        protocol.openRequest(compact, URI, "POST");
        assertEquals(1, listener.successes.get(), "首次请求应成功");

        listener.clear();
        EncryptorException error = assertThrows(EncryptorException.class,
            () -> protocol.openRequest(compact, URI, "POST"));

        assertEquals(EncryptorFailure.REPLAY, error.failure());
        assertEquals(0, listener.successes.get(), "重放不得再记一次解密成功");
        assertEquals(Collections.singletonList(EncryptorFailure.REPLAY), listener.failures,
            "重放必须进入失败回调（指标/日志依赖此分类）");
    }

    @Test
    void 过期不回调成功且回调EXPIRED失败() {
        long expired = System.currentTimeMillis() - DefaultProtocol.DEFAULT_TTL_MILLIS - 60_000L;
        String compact = seal(newNonce(), expired);

        EncryptorException error = assertThrows(EncryptorException.class,
            () -> protocol.openRequest(compact, URI, "POST"));

        assertEquals(EncryptorFailure.EXPIRED, error.failure());
        assertEquals(0, listener.successes.get(), "过期不得记成解密成功");
        assertEquals(Collections.singletonList(EncryptorFailure.EXPIRED), listener.failures);
    }

    @Test
    void 认证失败不消费nonce() throws Exception {
        String nonce = newNonce();
        String compact = seal(nonce, System.currentTimeMillis());

        EncryptorException error = assertThrows(EncryptorException.class,
            () -> protocol.openRequest(tamper(compact), URI, "POST"));
        assertEquals(EncryptorFailure.DECRYPT_FAILED, error.failure());

        // tag 校验失败发生在 nonce 消费之前：原报文必须仍可用
        protocol.openRequest(compact, URI, "POST");
        assertEquals(1, listener.successes.get(), "被篡改的报文不得污染 nonce 存储");
    }

    private static String newNonce() {
        return "n-" + UUID.randomUUID();
    }

    private static String seal(String nonce, long ts) {
        Map<String, Object> claims = ContextAad.claims(URI, "POST", Direction.REQUEST, ts, nonce);
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
            .keyID(KID)
            .customParams(claims)
            .build();
        JWEObject jwe = new JWEObject(header, new Payload("hello"));
        try {
            jwe.encrypt(new RSAEncrypter((RSAPublicKey) keyPair.getPublic()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return jwe.serialize();
    }

    private static String tamper(String compact) {
        String[] parts = compact.split("\\.");
        parts[3] = (parts[3].charAt(0) == 'A' ? 'B' : 'A') + parts[3].substring(1);
        return String.join(".", parts);
    }

    private static final class RecordingListener implements EncryptorListener {
        private final AtomicInteger successes = new AtomicInteger();
        private final List<EncryptorFailure> failures = new ArrayList<>();

        @Override
        public void onDecryptSuccess(JweContext context) {
            successes.incrementAndGet();
        }

        @Override
        public void onDecryptFailure(EncryptorFailure failure, Throwable cause) {
            failures.add(failure);
        }

        private void clear() {
            successes.set(0);
            failures.clear();
        }
    }
}
