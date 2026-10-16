package io.github.cuukenn.encryptor.web.filter;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Map;

/**
 * @author changgg
 */
public class EncryptorRequestParameterFilterTest {
    @Test
    public void test_parse_form_data_without_equal_sign() {
        // 原实现会对 "broken" 调用 substring(0, -1) 抛 StringIndexOutOfBoundsException
        Map<Object, Object> parameters = EncryptorRequestParameterFilter.parseFormData("a=1&broken");
        Assertions.assertEquals("1", parameters.get("a"));
        Assertions.assertEquals("", parameters.get("broken"));
    }

    @Test
    public void test_parse_form_data_duplicated_key_keeps_first_value() {
        // 原实现 Collectors.toMap 没有合并函数，重复 key 会抛 IllegalStateException
        Map<Object, Object> parameters = EncryptorRequestParameterFilter.parseFormData("a=1&a=2");
        Assertions.assertEquals("1", parameters.get("a"));
    }
}
