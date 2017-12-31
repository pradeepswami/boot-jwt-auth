package com.boot.jwt.key;

import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;

public class HMACKeystore implements Keystore {

    private String secret;
    private Key secretKey;

    public HMACKeystore(String secret) {
        this.secret = secret;
    }

    @Override
    public Key getPublicKey() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Key getAppPublicKey(String applicationName, String instanceId) {
        //TODO have a separate secret store
        return secretKey;
    }

    @Override
    public Key getPrivateKey() {
        return secretKey;
    }

    public void init() {
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(this.secret);
        secretKey = new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());
    }
}
