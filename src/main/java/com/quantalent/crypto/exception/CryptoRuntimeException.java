package com.quantalent.crypto.exception;

import com.quantalent.commons.exception.BaseRuntimeException;

public class CryptoRuntimeException extends BaseRuntimeException {

    public CryptoRuntimeException(String message) {
        super(message);
    }
    public CryptoRuntimeException(String message, Throwable e) {
        super(message, e);
    }

}
