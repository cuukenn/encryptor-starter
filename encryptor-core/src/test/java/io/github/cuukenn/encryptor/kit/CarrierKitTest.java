package io.github.cuukenn.encryptor.kit;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link CarrierKit} 契约测试：form 语义解码 / URI 形态编码 / query jwe 判定 / form body 提取。
 *
 * @author changgg
 */
class CarrierKitTest {

    @Test
    void form语义解码加号为空格() {
        assertEquals("a b", CarrierKit.decodeFormComponent("a+b"));
        assertEquals("张三", CarrierKit.decodeFormComponent("%E5%BC%A0%E4%B8%89"));
        assertThrows(IllegalArgumentException.class, () -> CarrierKit.decodeFormComponent("100%"));
    }

    @Test
    void uri形态编码空格为百分20() {
        assertEquals("a%20b", CarrierKit.encodeQueryComponent("a b"));
        assertEquals("%E5%BC%A0%E4%B8%89", CarrierKit.encodeQueryComponent("张三"));
        // 字面 + 编码为 %2B（与解码侧的 form 语义互逆）
        assertEquals("a%2Bb", CarrierKit.encodeQueryComponent("a+b"));
    }

    @Test
    void 编解码互逆() {
        for (String value : Arrays.asList("a b", "a+b", "张三", "x=1&2", "")) {
            assertEquals(value, CarrierKit.decodeFormComponent(CarrierKit.encodeQueryComponent(value)));
        }
    }

    @Test
    void 解析urlencoded保留多值与插入序() {
        Map<String, java.util.List<String>> parsed = CarrierKit.parseUrlencoded("a=1&b=2&a=3");
        assertEquals(Arrays.asList("1", "3"), parsed.get("a"));
        assertEquals(Arrays.asList("2"), parsed.get("b"));
        assertEquals(Arrays.asList("a", "b"), new java.util.ArrayList<>(parsed.keySet()),
            "插入序且键去重（重复键的多值合并在 value 列表里）");
        // 无值对：value 为空串；空段跳过
        assertTrue(CarrierKit.parseUrlencoded("flag&&x=1").containsKey("flag"));
        assertEquals("", CarrierKit.parseUrlencoded("flag").get("flag").get(0));
    }

    @Test
    void query上的jwe判定含编码形态() {
        assertTrue(CarrierKit.hasQueryJwe("jwe=abc", "jwe"));
        assertTrue(CarrierKit.hasQueryJwe("x=1&%6Awe=abc", "jwe"), "百分号编码的 name 也要识别");
        assertFalse(CarrierKit.hasQueryJwe("x=1", "jwe"));
        assertFalse(CarrierKit.hasQueryJwe(null, "jwe"));
        assertFalse(CarrierKit.hasQueryJwe("", "jwe"));
        // 值里出现 jwe= 不算命中（只看 name）
        assertFalse(CarrierKit.hasQueryJwe("x=jwe=1", "jwe"));
    }

    @Test
    void formBody提取jwe字段() {
        assertEquals("v1", CarrierKit.jweFromFormBody("a=1&jwe=v1".getBytes(StandardCharsets.UTF_8), "jwe"));
        assertNull(CarrierKit.jweFromFormBody("a=1".getBytes(StandardCharsets.UTF_8), "jwe"));
        assertNull(CarrierKit.jweFromFormBody(new byte[0], "jwe"));
        assertNull(CarrierKit.jweFromFormBody(null, "jwe"));
        assertEquals("a b", CarrierKit.jweFromFormBody("jwe=a+b".getBytes(StandardCharsets.UTF_8), "jwe"));
    }
}
