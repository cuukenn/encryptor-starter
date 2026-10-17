package io.github.cuukenn.encryptor.bench;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.Direction;
import io.github.cuukenn.encryptor.jose.ServerKeyStore;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * 基准公共支撑：RSA 密钥与请求 compact 的预构造。
 *
 * @author changgg
 */
final class BenchSupport {

    static final String URI = "/bench";
    static final String METHOD = "GET";
    static final String KID = "bench";
    static final byte[] PAYLOAD = "hello-bench".getBytes(StandardCharsets.UTF_8);

    private BenchSupport() {
    }

    static ServerKeyStore rsaStore() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        String priv = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
        String pub = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        return ServerKeyStore.builder().add(KID, priv, pub).activeKid(KID).build();
    }

    /** 构造一条合法请求 compact（ts 固定：codec 不做时间窗，防重放由 ReplayGuard 负责，不在基准范围）。 */
    static String seal(ServerKeyStore keys) {
        try {
            RSAKey rsaKey = keys.rsaKey(KID);
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID(KID)
                .customParams(ContextAad.claims(URI, METHOD, Direction.REQUEST, System.currentTimeMillis(), "nonce-bench"))
                .build();
            JWEObject object = new JWEObject(header, new Payload(PAYLOAD));
            object.encrypt(new RSAEncrypter((RSAPublicKey) rsaKey.toRSAPublicKey()));
            return object.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
