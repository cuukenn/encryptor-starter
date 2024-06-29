package io.github.cuukenn.encryptor.example.web.web;

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
}
