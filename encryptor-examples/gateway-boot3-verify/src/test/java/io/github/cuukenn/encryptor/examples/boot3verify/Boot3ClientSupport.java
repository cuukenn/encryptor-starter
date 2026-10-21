package io.github.cuukenn.encryptor.examples.boot3verify;

import cn.hutool.json.JSONUtil;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import io.github.cuukenn.encryptor.jose.ContextAad;
import io.github.cuukenn.encryptor.jose.Direction;
import io.github.cuukenn.encryptor.jose.KeyType;
import org.springframework.test.context.DynamicPropertyRegistry;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * Boot 3.5 验证的客户端支撑（测试侧）：沿用 javax 线 GatewayJweTest 的断言口径
 * （手工拼 compact + 解 dir 响应），差别在于 CEK 由测试自己生成并经 nimbus
 * {@code encrypt(header, cek)} 封入报文——真实传输下客户端可自解响应，
 * 不需要从服务端上下文里捞 CEK（链路经过真实 Netty，上下文不可直接引用）。
 *
 * @author changgg
 */
public final class Boot3ClientSupport {
    public static final String KID = "k1";

    private static volatile KeyPair pair;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Boot3ClientSupport() {
    }

    /** 两个测试 context（常规/超限）共用：密钥对 + 下游 base-uri。 */
    public static void registerDynamicProperties(DynamicPropertyRegistry registry) {
        ensurePair();
        registry.add("downstream.base-uri", DownstreamEchoServer::baseUri);
        registry.add("encryptor.config.reactive.keys[0].kid", () -> KID);
        registry.add("encryptor.config.reactive.keys[0].type", () -> KeyType.RSA.name());
        registry.add("encryptor.config.reactive.keys[0].private-key", Boot3ClientSupport::privateKeyB64);
        registry.add("encryptor.config.reactive.keys[0].public-key", Boot3ClientSupport::publicKeyB64);
    }

    private static void ensurePair() {
        if (pair != null) {
            return;
        }
        synchronized (Boot3ClientSupport.class) {
            if (pair != null) {
                return;
            }
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                pair = generator.generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static String privateKeyB64() {
        ensurePair();
        return Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
    }

    private static String publicKeyB64() {
        ensurePair();
        return Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
    }

    /** 已封装请求 + 客户端可见的 CEK（响应用同一把解）。 */
    public static final class Sealed {
        public final String compact;
        public final byte[] cek;

        Sealed(String compact, byte[] cek) {
            this.compact = compact;
            this.cek = cek;
        }
    }

    /** 三载体通用：测试自封请求报文（claims 与 ContextAad 同口径）。 */
    public static Sealed seal(String plaintext, String uri, String method) {
        ensurePair();
        long ts = System.currentTimeMillis();
        String nonce = UUID.randomUUID().toString();
        Map<String, Object> claims = ContextAad.claims(uri, method, Direction.REQUEST, ts, nonce);
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
            .keyID(KID).customParams(claims).build();
        String headerJson = header.toString();
        byte[] cek = new byte[32];
        RANDOM.nextBytes(cek);
        try {
            byte[] iv = new byte[12];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            // AAD = compact 首段（b64u header）的 ASCII 字节，与 gateway JweCodec 复算口径一致
            String headerSeg = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(ascii(headerJson));
            cipher.updateAAD(ascii(headerSeg));
            byte[] ctAndTag = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = Arrays.copyOfRange(ctAndTag, 0, ctAndTag.length - 16);
            byte[] tag = Arrays.copyOfRange(ctAndTag, ctAndTag.length - 16, ctAndTag.length);
            // RSA-OAEP-256 封 CEK —— JCE 显式给定 OAEP(SHA-256, MGF1-SHA-256) 参数，
            // 与 nimbus RSADecrypter 的 RSA-OAEP-256 语义对齐（LB 为空）
            String cekSeg = b64(wrapCekOaep256(cek));
            String compact = headerSeg + "." + cekSeg + "."
                + b64(iv) + "." + b64(ciphertext) + "." + b64(tag);
            return new Sealed(compact, cek);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    /** RSA-OAEP-256 封 CEK（与 nimbus RSADecrypter 对齐：SHA-256 哈希 + MGF1-SHA-256，LB 空）。 */
    private static byte[] wrapCekOaep256(byte[] cek) {
        try {
            // 显式写全参数：SunJCE 对 "OAEPWithSHA-256AndMGF1Padding" 的 MGF1 默认值有歧义
            javax.crypto.spec.OAEPParameterSpec spec = new javax.crypto.spec.OAEPParameterSpec(
                "SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256,
                javax.crypto.spec.PSource.PSpecified.DEFAULT);
            return rsaWrap(cek, spec);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** RSA-OAEP-256 封 CEK（SHA-256 哈希 + MGF1-SHA-256，LB 空）。 */
    private static byte[] rsaWrap(byte[] cek, javax.crypto.spec.OAEPParameterSpec spec) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, pair.getPublic(), spec);
        return rsa.doFinal(cek);
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** 改密文第一位（强制 GCM tag 校验失败 → AAD/DECRYPT 拒绝面）。 */
    public static String tamper(String compact) {
        String[] parts = compact.split("\\.");
        parts[2] = (parts[2].charAt(0) == 'A' ? 'B' : 'A') + parts[2].substring(1);
        return String.join(".", parts);
    }

    public static String formBody(Sealed sealed) {
        try {
            return "jwe=" + URLEncoder.encode(sealed.compact, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** 由 CEK 解 dir 响应（同 GatewayJweTest.decryptResponse：AAD = header 段 ASCII）。 */
    public static byte[] decryptResponse(String responsePayload, byte[] cek) {
        try {
            String compact = JSONUtil.parseObj(responsePayload).getStr("jwe");
            String[] parts = compact.split("\\.");
            byte[] iv = Base64.getUrlDecoder().decode(parts[2]);
            byte[] ciphertext = Base64.getUrlDecoder().decode(parts[3]);
            byte[] tag = Base64.getUrlDecoder().decode(parts[4]);
            byte[] ctAndTag = Arrays.copyOf(ciphertext, ciphertext.length + tag.length);
            System.arraycopy(tag, 0, ctAndTag, ciphertext.length, tag.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            cipher.updateAAD(parts[0].getBytes(StandardCharsets.US_ASCII));
            return cipher.doFinal(ctAndTag);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 响应 protected header JSON（断言 含 "res" 方向与 enc）。 */
    public static String responseHeaderJson(String responsePayload) {
        String compact = JSONUtil.parseObj(responsePayload).getStr("jwe");
        return new String(Base64.getUrlDecoder().decode(compact.split("\\.")[0]), StandardCharsets.US_ASCII);
    }

    /** 解响应 JSON 信封中的 jwe compact。 */
    public static String jweCompact(String responsePayload) {
        return JSONUtil.parseObj(responsePayload).getStr("jwe");
    }
}
