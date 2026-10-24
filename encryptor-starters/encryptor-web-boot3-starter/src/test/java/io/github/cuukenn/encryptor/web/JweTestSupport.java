package io.github.cuukenn.encryptor.web;

import cn.hutool.json.JSONUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.Base64URL;
import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.Direction;
import io.github.cuukenn.encryptor.jose.KeyType;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * 测试支撑：RSA 密钥 → DefaultProtocol；以客户端视角构造请求 JWE；以客户端视角解开响应 JWE。
 *
 * @author changgg
 */
public final class JweTestSupport {
    public static final String KID = "k1";
    private final PublicKey publicKey;
    public final DefaultProtocol protocol;

    public JweTestSupport() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            this.publicKey = pair.getPublic();
            String privateB64 = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
            String publicB64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
            this.protocol = DefaultProtocol.builder()
                .key(new DefaultProtocol.KeyMaterial(KID, KeyType.RSA, privateB64, publicB64))
                .build();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * EC(P-256) 变体：以 ECDH-ES（nimbus ECDHEncrypter 独立实现当 oracle）构造请求 JWE——
     * 过滤器层的 ECDH 覆盖此前只有 core 单测与手动 e2e。
     */
    public static final class Ec {
        public static final String KID = "ec-k1";
        public final DefaultProtocol protocol;

        public Ec() {
            try {
                java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
                generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
                KeyPair pair = generator.generateKeyPair();
                this.protocol = DefaultProtocol.builder()
                    .key(new DefaultProtocol.KeyMaterial(KID, KeyType.EC,
                        Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                        Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())))
                    .build();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        public String seal(String plaintext, String uri, String method) {
            try {
                java.security.interfaces.ECPublicKey pub = (java.security.interfaces.ECPublicKey)
                    protocol.keys().publicKeys().stream()
                        .filter(k -> KID.equals(k.kid())).findFirst()
                        .map(k -> java.util.Base64.getDecoder().decode(k.spkiBase64()))
                        .map(spki -> {
                            try {
                                return java.security.KeyFactory.getInstance("EC")
                                    .generatePublic(new java.security.spec.X509EncodedKeySpec(spki));
                            } catch (Exception e) {
                                throw new IllegalStateException(e);
                            }
                        }).orElseThrow(IllegalStateException::new);
                long ts = System.currentTimeMillis();
                String nonce = UUID.randomUUID().toString();
                Map<String, Object> claims = ContextAad.claims(uri, method, Direction.REQUEST, ts, nonce);
                JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.parse("ECDH-ES"), EncryptionMethod.A256GCM)
                    .keyID(KID)
                    .customParams(claims)
                    .build();
                JWEObject jwe = new JWEObject(header, new Payload(plaintext));
                jwe.encrypt(new com.nimbusds.jose.crypto.ECDHEncrypter(pub));
                return jwe.serialize();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /**
     * 客户端视角：用服务端公钥加密明文为请求 JWE（claims 与 ContextAad 一致）。
     */
    public String seal(String plaintext, String uri, String method) {
        long ts = System.currentTimeMillis();
        String nonce = UUID.randomUUID().toString();
        Map<String, Object> claims = ContextAad.claims(uri, method, Direction.REQUEST, ts, nonce);
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
            .keyID(KID)
            .customParams(claims)
            .build();
        JWEObject jwe = new JWEObject(header, new Payload(plaintext));
        try {
            jwe.encrypt(new RSAEncrypter((RSAPublicKey) publicKey));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        return jwe.serialize();
    }

    /**
     * 篡改 compact 的 IV 段（第 3 段）首字符 → GCM tag 必然不匹配。
     */
    public static String tamper(String compact) {
        String[] parts = compact.split("\\.");
        parts[2] = (parts[2].charAt(0) == 'A' ? 'B' : 'A') + parts[2].substring(1);
        return String.join(".", parts);
    }

    /**
     * 从响应负载 {"jwe":"…"} 取出 compact。
     */
    public static String responseCompact(String responsePayload) {
        return JSONUtil.parseObj(responsePayload).getStr("jwe");
    }

    /**
     * 客户端视角解开响应 JWE（alg=dir，CEK 即请求 CEK）。
     */
    public static byte[] decryptResponse(String responsePayload, byte[] cek) {
        try {
            String[] parts = responseCompact(responsePayload).split("\\.");
            byte[] iv = Base64.getUrlDecoder().decode(parts[2]);
            byte[] ciphertext = Base64.getUrlDecoder().decode(parts[3]);
            byte[] tag = Base64.getUrlDecoder().decode(parts[4]);
            byte[] ctAndTag = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, ctAndTag, 0, ciphertext.length);
            System.arraycopy(tag, 0, ctAndTag, ciphertext.length, tag.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            // JWE 的 AAD = protected header 的 ASCII 字节（RFC 7516），不带 AAD 解不开
            cipher.updateAAD(parts[0].getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return cipher.doFinal(ctAndTag);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * 读响应 compact 的 protected header（校验 dir=res 等）。
     */
    public static String responseHeaderJson(String responsePayload) {
        String[] parts = responseCompact(responsePayload).split("\\.");
        return new String(Base64.getUrlDecoder().decode(parts[0]));
    }
}
