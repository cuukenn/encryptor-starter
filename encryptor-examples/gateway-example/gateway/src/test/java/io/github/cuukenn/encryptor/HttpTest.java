package io.github.cuukenn.encryptor;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * v2 协议网关端到端脚本（需先启动 gateway-example:8080 与其下游 web:8082；surefire 已排除，不进 CI）。
 *
 * <p>网关解密后转发明文给下游，响应再由网关用请求 CEK 加密（alg=dir）。</p>
 *
 * @author changgg
 */
public class HttpTest {
    private static final Logger logger = LoggerFactory.getLogger(HttpTest.class);
    private static final String BASE = "http://127.0.0.1:8080";
    /** 与 gateway/src/main/resources/application.yml 的 {@code keys[0]}（gw-2026）一致。 */
    private static final String KID = "gw-2026";
    private static final String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjcE3M8vO96ijWHBgmwVLMowHSrZRIuOFzzGQkcCcku2iu7poY6iyvvms1yvmhwJLPImB7R7NF2UHqUVa56LR/vNTzp8Ec9IVqr3w9Uru/npqnb3OHB2KysZtw8Syvdb77FRAAtU69zj1j0DL672ZC2ZfGLITx577ohQjTMRnw8jErqQIzdxcyQw3MlDQymh5zi43dh3sQthqnm04CobxRJDYYjAbW45+jtR5gHgW+kQl+M21GRoXQpUPG6Nv6A5uHC5rfPu6i/fXpMUYrWRka277t/5JstzAbVMlHRgv9XAR+UtfJiUWwWy1LIbviv2oAbX7k3j0OPSXxjWp6qJ6QIDAQAB";
    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void test_get() {
        String plaintext = "name=" + URLEncoder.encode("小明", StandardCharsets.UTF_8);
        Sealed sealed = seal(plaintext, "/test/hello", "GET");
        HttpResponse response = HttpRequest.get(BASE + "/test/hello?jwe=" + url(sealed.compact)).execute();
        Assertions.assertEquals(200, response.getStatus(), "GET /test/hello 应返回 200");
        String body = decryptResponse(response.body(), sealed.cek);
        logger.info("decrypted: {}", body);
        Assertions.assertTrue(body.contains("Hello"), "响应应包含 Hello，实际为: " + body);
        Assertions.assertTrue(body.contains("小明"), "响应回显 name=小明，实际为: " + body);
    }

    @Test
    public void test_post() {
        Sealed sealed = seal("{\"name\":\"小明\"}", "/test/hello", "POST");
        HttpResponse response = HttpRequest.post(BASE + "/test/hello")
                .header("Content-Type", "application/json")
                .body("{\"jwe\":\"" + sealed.compact + "\"}").execute();
        Assertions.assertEquals(200, response.getStatus(), "POST /test/hello 应返回 200");
        String body = decryptResponse(response.body(), sealed.cek);
        logger.info("decrypted: {}", body);
        Assertions.assertTrue(body.contains("Hello"), "响应应包含 Hello，实际为: " + body);
        Assertions.assertTrue(body.contains("小明"), "响应回显 name=小明，实际为: " + body);
    }

    @Test
    public void test_tampered_rejected() {
        String plaintext = "name=" + URLEncoder.encode("小明", StandardCharsets.UTF_8);
        Sealed sealed = seal(plaintext, "/test/hello", "GET");
        // 篡改密文段首字符 → GCM tag 校验失败 → 400
        String[] parts = sealed.compact.split("\\.");
        char first = parts[3].charAt(0);
        parts[3] = (first == 'A' ? 'B' : 'A') + parts[3].substring(1);
        HttpResponse response = HttpRequest.get(BASE + "/test/hello?jwe=" + url(String.join(".", parts))).execute();
        logger.info("tampered status: {}, body: {}", response.getStatus(), response.body());
        Assertions.assertEquals(400, response.getStatus(), "篡改报文应被拒（400）");
    }

    // ==================== 构造/解密工具（与 web-example/HttpTest 同构） ====================

    private static final class Sealed {
        final String compact;
        final byte[] cek;

        Sealed(String compact, byte[] cek) {
            this.compact = compact;
            this.cek = cek;
        }
    }

    private static Sealed seal(String plaintext, String uri, String method) {
        try {
            byte[] cek = new byte[32];
            RANDOM.nextBytes(cek);
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("uri", uri);
            claims.put("m", method);
            claims.put("dir", "req");
            claims.put("ts", System.currentTimeMillis());
            claims.put("nonce", Base64URL.encode(randomBytes(12)).toString());
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                    .keyID(KID).customParams(claims).build();
            String headerSegment = header.toBase64URL().toString();
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey(),
                    new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            byte[] encryptedKey = rsa.doFinal(cek);
            byte[] iv = randomBytes(12);
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            gcm.updateAAD(headerSegment.getBytes(StandardCharsets.US_ASCII));
            byte[] ctTag = gcm.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] ct = Arrays.copyOfRange(ctTag, 0, ctTag.length - 16);
            byte[] tag = Arrays.copyOfRange(ctTag, ctTag.length - 16, ctTag.length);
            String compact = headerSegment + '.'
                    + Base64URL.encode(encryptedKey) + '.'
                    + Base64URL.encode(iv) + '.'
                    + Base64URL.encode(ct) + '.'
                    + Base64URL.encode(tag);
            return new Sealed(compact, cek);
        } catch (Exception e) {
            throw new IllegalStateException("构造请求 JWE 失败", e);
        }
    }

    private static PublicKey publicKey() throws Exception {
        return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY)));
    }

    private static byte[] randomBytes(int n) {
        byte[] bytes = new byte[n];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static String url(String compact) {
        return URLEncoder.encode(compact, StandardCharsets.UTF_8);
    }

    private static String decryptResponse(String body, byte[] cek) {
        try {
            // body = {"jwe":"<compact>"}；响应 alg=dir，CEK 复用请求的
            String compact = body.substring(body.indexOf('"') + 1);
            compact = compact.substring(compact.indexOf('"') + 1, compact.lastIndexOf('"'));
            String[] parts = compact.split("\\.");
            byte[] iv = Base64.getUrlDecoder().decode(parts[2]);
            byte[] ct = Base64.getUrlDecoder().decode(parts[3]);
            byte[] tag = Base64.getUrlDecoder().decode(parts[4]);
            byte[] ctTag = new byte[ct.length + tag.length];
            System.arraycopy(ct, 0, ctTag, 0, ct.length);
            System.arraycopy(tag, 0, ctTag, ct.length, tag.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            cipher.updateAAD(parts[0].getBytes(StandardCharsets.US_ASCII));
            return new String(cipher.doFinal(ctTag), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("解响应失败: " + body, e);
        }
    }
}
