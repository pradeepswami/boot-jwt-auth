package com.boot.jwt.core.key;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Objects;

public class HMACKeystore implements Keystore {

    private Key secretKey;

    public HMACKeystore(String base64Key) {
        Objects.requireNonNull(base64Key, "HMAC key string is null");
        byte[] decodedKey = TextCodec.BASE64.decode(base64Key);
        secretKey = new SecretKeySpec(decodedKey, SignatureAlgorithm.HS256.getJcaName());
    }

    public HMACKeystore(Key key) {
        this.secretKey = key;
    }

    @Override
    public Key getPublicKey() {
        throw new UnsupportedOperationException();
    }


    @Override
    public Key getPrivateKey() {
        return secretKey;
    }

}
