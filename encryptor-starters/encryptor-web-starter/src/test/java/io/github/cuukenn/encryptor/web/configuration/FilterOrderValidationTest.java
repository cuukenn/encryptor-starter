package io.github.cuukenn.encryptor.web.configuration;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.web.config.WebFilterConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 过滤器 order 链序契约的启动期校验：order 全部可配，但相对顺序错了不报错而是
 * <b>静默退化</b>（视图过滤器看到密文原文、响应过滤器拿不到 CEK 时 fail-open 放行明文），
 * 因此必须在装配期拒绝。默认值已由 {@code FilterChainOrderTest} 钉住，这里钉"用户改过的值"。
 *
 * @author changgg
 */
class FilterOrderValidationTest {

    @Test
    void 默认order满足链序契约() {
        assertDoesNotThrow(() -> WebEncryptorConfiguration.validateFilterOrder(new WebFilterConfig()));
    }

    @Test
    void 门面跑到视图过滤器之后时启动失败() {
        WebFilterConfig orders = new WebFilterConfig();
        orders.setEncryptorFilterOrder(0);

        EncryptorException e = assertThrows(EncryptorException.class,
            () -> WebEncryptorConfiguration.validateFilterOrder(orders));
        assertTrue(e.getMessage().contains("门面"), e.getMessage());
    }

    @Test
    void 响应过滤器跑到参数过滤器之外时启动失败() {
        // 参数过滤器的 finally 清掉整个 WebContext（含 CEK）：响应过滤器必须嵌在它之内
        WebFilterConfig orders = new WebFilterConfig();
        orders.setEncryptorResFilterOrder(-12);

        EncryptorException e = assertThrows(EncryptorException.class,
            () -> WebEncryptorConfiguration.validateFilterOrder(orders));
        assertTrue(e.getMessage().contains("响应"), e.getMessage());
    }

    @Test
    void 整体平移保持相对顺序时仍然合法() {
        // 下游要在更外层跑自己的过滤器（如认证在 -100）时，五个值必须整体平移
        WebFilterConfig orders = new WebFilterConfig();
        orders.setJwksFilterOrder(-103);
        orders.setEncryptorFilterOrder(-102);
        orders.setEncryptorReqParamsFilterOrder(-101);
        orders.setEncryptorReqBodyFilterOrder(-100);
        orders.setEncryptorResFilterOrder(-90);

        assertDoesNotThrow(() -> WebEncryptorConfiguration.validateFilterOrder(orders));
    }

    @Test
    void 两个过滤器同序时启动失败() {
        WebFilterConfig orders = new WebFilterConfig();
        orders.setEncryptorReqParamsFilterOrder(orders.getEncryptorReqBodyFilterOrder());

        assertThrows(EncryptorException.class, () -> WebEncryptorConfiguration.validateFilterOrder(orders));
    }
}
