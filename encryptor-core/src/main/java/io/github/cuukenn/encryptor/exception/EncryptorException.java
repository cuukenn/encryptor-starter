package io.github.cuukenn.encryptor.exception;

public class EncryptorException extends RuntimeException {
    public EncryptorException() {
    }

    public EncryptorException(String message) {
        super(message);
    }

    public EncryptorException(String message, Throwable cause) {
        super(message, cause);
    }

    public EncryptorException(Throwable cause) {
        super(cause);
    }

    public EncryptorException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
