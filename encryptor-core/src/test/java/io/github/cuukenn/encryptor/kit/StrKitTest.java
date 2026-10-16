package io.github.cuukenn.encryptor.kit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 锁定 black-uris / crypto-config 这类"正则 key"的匹配契约。
 *
 * <p>这套契约是使用方最容易踩的坑：匹配是<b>整串</b>匹配（等价 {@code Pattern.matches}），
 * 且多规则命中时按"最长正则优先、等长按声明顺序"取值。</p>
 *
 * @author changgg
 */
public class StrKitTest {
    @Test
    public void test_any_match_is_full_match_not_contains() {
        Assertions.assertTrue(StrKit.anyMatch("/api", Arrays.asList("/api")));
        // 前缀不匹配："regex=/api" 不匹配 "/api2/x"
        Assertions.assertFalse(StrKit.anyMatch("/api2/x", Arrays.asList("/api")));
        // 也不是 find："regex=api" 不匹配 "/x/api/y"
        Assertions.assertFalse(StrKit.anyMatch("/x/api/y", Arrays.asList("api")));
        // 想前缀/包含匹配必须自己写 .*
        Assertions.assertTrue(StrKit.anyMatch("/x/api/y", Arrays.asList(".*api.*")));
    }

    @Test
    public void test_best_match_prefers_the_longest_matching_regex() {
        Map<String, Object> selectable = new LinkedHashMap<>();
        selectable.put("^/test/.*", "wide");
        selectable.put("^/test/hello.*", "narrow");

        Assertions.assertEquals("^/test/hello.*", StrKit.getBestMatchStr("/test/hello", selectable.keySet()));
    }

    @Test
    public void test_best_match_equal_length_is_resolved_by_declaration_order() {
        // 等长候选只能留一个：契约是"先声明者优先"，而不是"碰集合迭代顺序的运气"
        List<String> firstDeclaredFirst = Arrays.asList("^/test/hello$", "^/test/hell.*");
        Assertions.assertEquals("^/test/hello$", StrKit.getBestMatchStr("/test/hello", firstDeclaredFirst));

        List<String> otherDeclaredFirst = Arrays.asList("^/test/hell.*", "^/test/hello$");
        Assertions.assertEquals("^/test/hell.*", StrKit.getBestMatchStr("/test/hello", otherDeclaredFirst));
    }

    @Test
    public void test_best_match_returns_null_when_nothing_matches() {
        Assertions.assertNull(StrKit.getBestMatchStr("/pay", Arrays.asList("^/test/.*")));
        Assertions.assertNull(StrKit.getBestMatchStr("/test", null));
    }
}
