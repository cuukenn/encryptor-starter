package io.github.cuukenn.encryptor.reactive.gateway.converter;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

/**
 * @author changgg
 */
public class FormMessageConverterTest {
    @Test
    public void test_form_content_type_with_charset_is_readable() {
        // 网关侧这是硬故障：识别不出表单会 fallback 到 JSON 解析，直接 500
        FormMessageConverter converter = new FormMessageConverter();
        Assertions.assertTrue(converter.canRead(MediaType.valueOf("application/x-www-form-urlencoded;charset=UTF-8")));
        Assertions.assertTrue(converter.canWrite(MediaType.valueOf("application/x-www-form-urlencoded;charset=UTF-8")));
    }
}
