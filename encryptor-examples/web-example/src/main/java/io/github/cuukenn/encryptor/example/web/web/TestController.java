package io.github.cuukenn.encryptor.example.web.web;

import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * @author changgg
 */
@RestController
@RequestMapping("/test")
public class TestController {
    @GetMapping("/hello")
    public String hello(@RequestParam(name = "name", required = false) String name) {
        return "Hello, " + name;
    }

    /**
     * uri 级 crypto-config 覆盖（{@code ^/test/secret.*}）的目标端点。
     *
     * <p>刻意与 {@code /test/hello} 分开：{@code /test/hello} 走全局默认密钥，
     * 本端点走 {@code encryptor.config.web.crypto-config} 里那对覆盖密钥，
     * 从而"用了哪套密钥"是可判定的。</p>
     */
    @GetMapping("/secret")
    public String secret(@RequestParam(name = "name", required = false) String name) {
        return "Secret, " + name;
    }

    /**
     * uri 级 crypto-config 覆盖（{@code ^/test/ec.*}）的目标端点：只接受 ECDH-ES(P-256) 那把密钥。
     */
    @GetMapping("/ec")
    public String ec(@RequestParam(name = "name", required = false) String name) {
        return "EC, " + name;
    }

    /**
     * uri 级 crypto-config 覆盖（{@code ^/test/sm.*}）的目标端点：只接受 SM2 那把密钥。
     * 浏览器 WebCrypto 没有 SM 算法，需用国密客户端验证（见 README「国密的客户端」）。
     */
    @GetMapping("/sm")
    public String sm(@RequestParam(name = "name", required = false) String name) {
        return "SM, " + name;
    }

    @PostMapping("/hello")
    public String hello(@RequestBody Map<String, Object> data) {
        return "Hello, " + data;
    }

    @PostMapping(value = "/hello", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public String helloForm(@RequestBody MultiValueMap<String, Object> data) {
        return "Hello, " + data;
    }
}
