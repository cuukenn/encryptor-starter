package io.github.cuukenn.encryptor.exception;

public class EncryptorException extends RuntimeException {

    /** 失败分类，可为 null（老调用点没有分类）。 */
    private final EncryptorFailure failure;

    public EncryptorException() {
        this.failure = null;
    }

    public EncryptorException(String message) {
        super(message);
        this.failure = null;
    }

    public EncryptorException(String message, Throwable cause) {
        super(message, cause);
        this.failure = null;
    }

    public EncryptorException(Throwable cause) {
        super(cause);
        this.failure = null;
    }

    public EncryptorException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
        this.failure = null;
    }

    public EncryptorException(EncryptorFailure failure, String message) {
        super(message);
        this.failure = failure;
    }

    public EncryptorException(EncryptorFailure failure, String message, Throwable cause) {
        super(message, cause);
        this.failure = failure;
    }

    public EncryptorFailure failure() {
        return failure;
    }
}
