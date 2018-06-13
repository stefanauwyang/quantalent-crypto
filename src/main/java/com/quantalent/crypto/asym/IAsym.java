package com.quantalent.crypto.asym;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface IAsym {

    KeyPair getKeyPair();

    void setKeyPair(KeyPair keyPair);

    PrivateKey getPrivateKey();

    void setPrivateKey(PrivateKey privateKey);

    PublicKey getPublicKey();

    void setPublicKey(PublicKey publicKey);
}
