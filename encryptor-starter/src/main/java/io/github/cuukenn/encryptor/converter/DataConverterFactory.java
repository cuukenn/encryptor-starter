package io.github.cuukenn.encryptor.converter;

/**
 * @author changgg
 */
public interface DataConverterFactory<T> {
    DataConverter apply(T config);
}