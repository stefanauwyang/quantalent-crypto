package com.quantalent.crypto.asymmetric;

import com.quantalent.crypto.AsymCryptoService;

public abstract class BaseAsymCryptoService implements AsymCryptoService {

    private String algorithm;
    private String provider;

    BaseAsymCryptoService(String algorithm) {
        this.algorithm = algorithm;
    }

    BaseAsymCryptoService(String algorithm, String provider) {
        this.algorithm = algorithm;
        this.provider = provider;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getProvider() {
        return provider;
    }

}
