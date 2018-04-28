package com.quantalent.crypto.exception;

import com.quantalent.commons.exception.BaseException;

public class CryptoException extends BaseException {

    public CryptoException(String message) {
        super(message);
    }
    public CryptoException(String message, Throwable e) {
        super(message, e);
    }

}
