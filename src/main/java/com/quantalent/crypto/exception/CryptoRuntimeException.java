package com.quantalent.crypto.exception;

import com.quantalent.commons.ErrorCode;
import com.quantalent.commons.exception.BaseRuntimeException;

public class CryptoRuntimeException extends BaseRuntimeException {

    public CryptoRuntimeException(String message) {
        super(message);
        this.errorCode = ErrorCode.FAIL;
    }

    public CryptoRuntimeException(String message, Throwable e) {
        super(message, e);
        this.errorCode = ErrorCode.FAIL;
    }

    public CryptoRuntimeException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public CryptoRuntimeException(ErrorCode errorCode, String message, Throwable e) {
        super(errorCode, message, e);
    }

}
