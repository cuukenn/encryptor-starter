package io.github.cuukenn.encryptor.web.converter;

import org.springframework.http.MediaType;

/**
 * @author changgg
 */
public class DefaultMessageConverter implements MessageReader, MessageWriter {
    private final MessageReader readerDelegate;
    private final MessageWriter writerDelegate;

    public DefaultMessageConverter() {
        JsonMessageConverter jsonMessageConverter = new JsonMessageConverter();
        this.readerDelegate = jsonMessageConverter;
        this.writerDelegate = jsonMessageConverter;
    }

    @Override
    public boolean canRead(MediaType mediaType) {
        return false;
    }

    @Override
    public RewriteFunction<byte[], byte[]> read() {
        return readerDelegate.read();
    }

    @Override
    public boolean canWrite(MediaType mediaType) {
        return false;
    }

    @Override
    public RewriteFunction<byte[], byte[]> write() {
        return writerDelegate.write();
    }
}
