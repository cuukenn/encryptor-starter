package io.github.cuukenn.encryptor.facade;

/**
 * @author changgg
 */
public interface IDataConverterFactory<T, D extends IDataConverter> {
    D apply(T config);
}