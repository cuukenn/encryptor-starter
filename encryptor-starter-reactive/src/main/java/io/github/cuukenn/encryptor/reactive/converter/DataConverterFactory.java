package io.github.cuukenn.encryptor.reactive.converter;

/**
 * @author changgg
 */
public interface DataConverterFactory<T> {
    DataConverter apply(T config);
}
