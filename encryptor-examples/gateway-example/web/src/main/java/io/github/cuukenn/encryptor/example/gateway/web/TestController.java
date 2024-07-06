package io.github.cuukenn.encryptor.example.gateway.web;

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

    @PostMapping("/hello")
    public String hello(@RequestBody Map<String, Object> data) {
        return "Hello, " + data;
    }

    @PostMapping(value = "/hello", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public String helloForm(@RequestBody MultiValueMap<String, Object> data) {
        return "Hello, " + data;
    }
}
