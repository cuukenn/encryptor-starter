package io.github.cuukenn.encryptor.example.boot3;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.springframework.test.context.DynamicPropertyRegistry;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * boot3 网关示例的客户端支撑（测试侧）：沿用 javax 线 GatewayJweTest 的断言口径
 * （手工拼 compact + 解 dir 响应），CEK 由测试自生成并按 RSA-OAEP-256 封入报文。
 *
 * <p>测试不另造密钥：封装用的 RSAPublicKey 直接从本网关 JWKS 发现端点取
 * activeKid 公钥——与 node 前端 {@code front/test.js} 同一条获取路径，
 * 示例 application.yml 的演示密钥（gw-2026）本身即被端到端验证。</p>
 *
 * @author changgg
 */
public final class Boot3ClientSupport {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    private Boot3ClientSupport() {
    }

    /** 测试 context 共用：动态下游 base-uri（密钥/activeKid 都来自 application.yml 的演示密钥）。 */
    public static void registerDynamicProperties(DynamicPropertyRegistry registry) {
        registry.add("downstream.base-uri", DownstreamEchoServer::baseUri);
    }

    /** 已发现的 active 密钥（与前端 jwe.fetchKeys→currentKey 同语义）。 */
    public static final class ActiveKey {
        public final String kid;
        public final RSAPublicKey publicKey;

        ActiveKey(String kid, RSAPublicKey publicKey) {
            this.kid = kid;
            this.publicKey = publicKey;
        }
    }

    /** 从网关 JWKS 发现端点取 activeKid 的 RSA 公钥。 */
    public static ActiveKey fetchActiveKey(int serverPort) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("http://127.0.0.1:" + serverPort + "/.well-known/encryptor-keys"))
            .GET().build();
        String body = HTTP.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)).body();
        Map<String, Object> root = JSONObjectUtils.parse(body);
        String activeKid = String.valueOf(root.get("activeKid"));
        List<?> keys = (List<?>) root.get("keys");
        for (Object item : keys) {
            @SuppressWarnings("unchecked")
            Map<String, Object> jwkMap = (Map<String, Object>) item;
            JWK jwk = JWK.parse(JSONObjectUtils.toJSONString(jwkMap));
            if (jwk.getKeyID().equals(activeKid)) {
                return new ActiveKey(activeKid, ((RSAKey) jwk).toRSAPublicKey());
            }
        }
        throw new IllegalStateException("JWKS 缺少 activeKid=" + activeKid + " 对应的公钥: " + body);
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

    /** 三载体通用：测试自封请求报文（claims 与 ContextAad 同口径；CEK 32B → A256GCM）。 */
    public static Sealed seal(String plaintext, String uri, String method, ActiveKey key) {
        long ts = System.currentTimeMillis();
        String nonce = UUID.randomUUID().toString();
        Map<String, Object> claims = io.github.cuukenn.encryptor.jose.ContextAad.claims(
            uri, method, io.github.cuukenn.encryptor.jose.Direction.REQUEST, ts, nonce);
        com.nimbusds.jose.JWEHeader header = new com.nimbusds.jose.JWEHeader.Builder(
            com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256, com.nimbusds.jose.EncryptionMethod.A256GCM)
            .keyID(key.kid).customParams(claims).build();
        String headerJson = header.toString();
        byte[] cek = new byte[32];
        RANDOM.nextBytes(cek);
        try {
            byte[] iv = new byte[12];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            // AAD = compact 首段（b64u header）的 ASCII 字节，与网关 JweCodec 复算口径一致
            String headerSeg = b64(ascii(headerJson));
            cipher.updateAAD(ascii(headerSeg));
            byte[] ctAndTag = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = Arrays.copyOfRange(ctAndTag, 0, ctAndTag.length - 16);
            byte[] tag = Arrays.copyOfRange(ctAndTag, ctAndTag.length - 16, ctAndTag.length);
            // RSA-OAEP-256 封 CEK —— JCE 显式给定 OAEP(SHA-256, MGF1-SHA-256) 参数，
            // 与 nimbus RSADecrypter 的 RSA-OAEP-256 语义对齐（LB 为空）
            String cekSeg = b64(wrapCekOaep256(cek, key.publicKey));
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

    /** RSA-OAEP-256 封 CEK（SHA-256 哈希 + MGF1-SHA-256，LB 空；SunJCE 默认 MGF1 有歧义，显式写全）。 */
    private static byte[] wrapCekOaep256(byte[] cek, RSAPublicKey publicKey) throws Exception {
        OAEPParameterSpec spec = new OAEPParameterSpec(
            "SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256,
            javax.crypto.spec.PSource.PSpecified.DEFAULT);
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, publicKey, spec);
        return rsa.doFinal(cek);
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** 改密文段第一位（强制 GCM tag 校验失败 → AAD/DECRYPT 拒绝面）。 */
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

    /** 由 CEK 解 dir 响应（同 GatewayJweTest.decryptResponse：AAD = protected header 段 ASCII）。 */
    public static byte[] decryptResponse(String responsePayload, byte[] cek) {
        try {
            String compact = jweCompact(responsePayload);
            String[] parts = compact.split("\\.");
            byte[] iv = Base64.getUrlDecoder().decode(parts[2]);
            byte[] ciphertext = Base64.getUrlDecoder().decode(parts[3]);
            byte[] tag = Base64.getUrlDecoder().decode(parts[4]);
            byte[] ctAndTag = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, ctAndTag, 0, ciphertext.length);
            System.arraycopy(tag, 0, ctAndTag, ciphertext.length, tag.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            cipher.updateAAD(parts[0].getBytes(StandardCharsets.US_ASCII));
            return cipher.doFinal(ctAndTag);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** 解响应 JSON 信封中的 jwe compact（信封 = {"jwe":"<compact>"}）。 */
    public static String jweCompact(String responsePayload) {
        try {
            return String.valueOf(com.nimbusds.jose.util.JSONObjectUtils.parse(responsePayload).get("jwe"));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
