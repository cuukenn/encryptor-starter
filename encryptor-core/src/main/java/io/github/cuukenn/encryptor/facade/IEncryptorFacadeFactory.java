package io.github.cuukenn.encryptor.facade;

/**
 * @author changgg
 */
public interface IEncryptorFacadeFactory<T> {
    EncryptorFacade apply(T config);
}
