package com.quantalent.crypto;

public enum Algorithm {
    KEY_AES("AES"),
    KEY_RSA("RSA"),
    CIPHER_RSA_ECB_PKCS1Padding("RSA/ECB/PKCS1Padding"),
    SIGN_SHA256withRSA("SHA256withRSA");

    private String value;

    Algorithm(String value) { this.value = value; }

    public String getValue() { return value; }

}
