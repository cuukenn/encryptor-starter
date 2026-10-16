package io.github.cuukenn.encryptor.web.converter;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Map;

/**
 * @author changgg
 */
public class FormMessageConverterTest {
    @Test
    public void test_parse_form_value_without_equal_sign() {
        // 原实现会对 "broken" 调用 substring(0, -1) 抛 StringIndexOutOfBoundsException
        Map<String, String> parameters = FormMessageConverter.parseForm("nonce=1&broken");
        Assertions.assertEquals("1", parameters.get("nonce"));
        Assertions.assertEquals("", parameters.get("broken"));
    }

    @Test
    public void test_parse_form_duplicated_key_keeps_first_value() {
        Map<String, String> parameters = FormMessageConverter.parseForm("data=1&data=2");
        Assertions.assertEquals("1", parameters.get("data"));
    }
}
