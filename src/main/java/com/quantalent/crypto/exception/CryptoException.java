package com.quantalent.crypto.exception;

import com.quantalent.commons.ErrorCode;
import com.quantalent.commons.exception.BaseException;

public class CryptoException extends BaseException {

    public CryptoException(String message) {
        super(message);
        this.errorCode = ErrorCode.FAIL;
    }

    public CryptoException(String message, Throwable e) {
        super(message, e);
        this.errorCode = ErrorCode.FAIL;
    }

    public CryptoException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }
    public CryptoException(ErrorCode errorCode, String message, Throwable e) {
        super(errorCode, message, e);
    }

}
