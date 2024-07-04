package io.github.cuukenn.encryptor.web.converter;

import org.springframework.http.MediaType;

/**
 * @author changgg
 */
public interface MessageReader {
    /**
     * 是否可读
     *
     * @param mediaType 媒体类型
     * @return 结果
     */
    boolean canRead(MediaType mediaType);

    /**
     * 读取策略
     *
     * @return 策略
     */
    RewriteFunction<byte[], byte[]> read();
}
