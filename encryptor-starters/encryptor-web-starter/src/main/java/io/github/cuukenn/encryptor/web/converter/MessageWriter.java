package io.github.cuukenn.encryptor.web.converter;

import org.springframework.http.MediaType;

/**
 * @author changgg
 */
public interface MessageWriter {
    /**
     * 是否可写
     *
     * @param mediaType 媒体类型
     * @return 结果
     */
    boolean canWrite(MediaType mediaType);

    /**
     * 写策略
     *
     * @return 策略
     */
    RewriteFunction<byte[], byte[]> write();
}
