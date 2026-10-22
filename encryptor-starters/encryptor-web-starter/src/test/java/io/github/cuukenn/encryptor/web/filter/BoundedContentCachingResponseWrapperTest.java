package io.github.cuukenn.encryptor.web.filter;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * 有界响应包装：父类 {@code setContentLength}/{@code setBufferSize} 会先 resize 预分配，
 * 必须在分配发生之前拦截，否则 4MiB 上限对"声明长度"形同虚设。
 *
 * @author changgg
 */
class BoundedContentCachingResponseWrapperTest {

    @Test
    void 声明超过上限的ContentLength只置溢出不预分配() {
        BoundedContentCachingResponseWrapper wrapper =
            new BoundedContentCachingResponseWrapper(new MockHttpServletResponse(), 1024);
        wrapper.setContentLengthLong(100L * 1024 * 1024);
        assertThat(wrapper.isOverflow()).isTrue();
    }

    @Test
    void 声明超过Integer上限且未配置上限时不抛异常() {
        BoundedContentCachingResponseWrapper wrapper =
            new BoundedContentCachingResponseWrapper(new MockHttpServletResponse(), Long.MAX_VALUE);
        assertThatCode(() -> wrapper.setContentLengthLong(3L * 1024 * 1024 * 1024))
            .doesNotThrowAnyException();
        assertThat(wrapper.isOverflow()).isFalse();
    }

    @Test
    void 超过上限的bufferSize收敛到上限且不误判溢出() throws Exception {
        BoundedContentCachingResponseWrapper wrapper =
            new BoundedContentCachingResponseWrapper(new MockHttpServletResponse(), 1024);
        wrapper.setBufferSize(64 * 1024 * 1024);
        assertThat(wrapper.isOverflow()).isFalse();
        wrapper.getOutputStream().write(new byte[8]);
        assertThat(wrapper.getContentSize()).isEqualTo(8);
    }

    @Test
    void 未超限的声明长度与bufferSize正常透传() throws Exception {
        BoundedContentCachingResponseWrapper wrapper =
            new BoundedContentCachingResponseWrapper(new MockHttpServletResponse(), 1024);
        wrapper.setContentLength(512);
        wrapper.setBufferSize(256);
        wrapper.getOutputStream().write(new byte[10]);
        assertThat(wrapper.isOverflow()).isFalse();
        assertThat(wrapper.getContentSize()).isEqualTo(10);
    }
}
