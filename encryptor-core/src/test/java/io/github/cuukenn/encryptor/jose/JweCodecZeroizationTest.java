package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 失败路径的密钥材料清零契约：CEK 一旦交给套件，任何失败分支都不得把它留在堆里。
 *
 * @author changgg
 */
class JweCodecZeroizationTest {

    private static final String KID = "k1";
    private static final String URI = "/pay/x";

    private static KeyPair keyPair;
    private static ServerKeyStore store;

    @BeforeAll
    static void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        store = ServerKeyStore.builder()
            .add(KID,
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()),
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()))
            .activeKid(KID)
            .build();
    }

    @Test
    void AEAD失败后CEK被清零() throws Exception {
        byte[] cek = new byte[32];
        Arrays.fill(cek, (byte) 7);
        JweCodec codec = codec(new CapturingSuite(cek, true));

        assertThrows(EncryptorException.class, () -> codec.decryptRequest(compact(), URI, "POST"));

        assertArrayEquals(new byte[32], cek, "AEAD 失败后 CEK 必须清零");
    }

    @Test
    void CEK长度非法时也被清零() throws Exception {
        byte[] cek = new byte[16];
        Arrays.fill(cek, (byte) 7);
        JweCodec codec = codec(new CapturingSuite(cek, false));

        assertThrows(EncryptorException.class, () -> codec.decryptRequest(compact(), URI, "POST"));

        assertArrayEquals(new byte[16], cek, "长度校验失败后 CEK 必须清零");
    }

    private static JweCodec codec(CipherSuite suite) {
        return new JweCodec(store, Collections.singletonList(suite),
            Collections.singleton("RSA-OAEP-256"), Collections.singleton("A256GCM"));
    }

    private static String compact() {
        Map<String, Object> claims = ContextAad.claims(URI, "POST", Direction.REQUEST,
            System.currentTimeMillis(), "n1");
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

    /** 解封时返回固定 CEK 引用，AEAD 固定失败（或返回长度非法的 CEK）。 */
    private static final class CapturingSuite implements CipherSuite {
        private final JceCipherSuite delegate = new JceCipherSuite();
        private final byte[] cek;
        private final boolean validLength;

        private CapturingSuite(byte[] cek, boolean validLength) {
            this.cek = cek;
            this.validLength = validLength;
        }

        @Override
        public Set<String> algorithms() {
            return delegate.algorithms();
        }

        @Override
        public Set<String> encryptionMethods() {
            return delegate.encryptionMethods();
        }

        @Override
        public byte[] unwrapCek(ServerKeyStore keys, String kid, String alg, byte[] encryptedKey) {
            return cek;
        }

        @Override
        public byte[] aeadEncrypt(String enc, byte[] cek, byte[] iv, byte[] plaintext, byte[] aad) throws Exception {
            return delegate.aeadEncrypt(enc, cek, iv, plaintext, aad);
        }

        @Override
        public byte[] aeadDecrypt(String enc, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag, byte[] aad)
            throws Exception {
            if (!validLength) {
                throw new GeneralSecurityException("invalid key length");
            }
            throw new GeneralSecurityException("tag mismatch");
        }

        @Override
        public int keyLength(String enc) {
            return delegate.keyLength(enc);
        }

        @Override
        public int tagLength(String enc) {
            return delegate.tagLength(enc);
        }

        @Override
        public int ivLength(String enc) {
            return delegate.ivLength(enc);
        }
    }
}
