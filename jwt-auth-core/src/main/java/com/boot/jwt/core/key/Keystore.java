package com.boot.jwt.core.key;

import java.security.Key;

public interface Keystore {

    Key getPublicKey();

    Key getPrivateKey();
}
