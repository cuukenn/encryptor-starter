package io.github.cuukenn.encryptor.facade;

/**
 * @author changgg
 */
public interface EncryptorFacadeFactory<T> {
    EncryptorFacade apply(T config);
}
