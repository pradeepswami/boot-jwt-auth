package com.boot.jwt.core.key;

import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAKeystore implements Keystore {

    private final static Logger LOG = LoggerFactory.getLogger(RSAKeystore.class);

    public static final int KEY_SIZE_IN_BITS = 2048;
    private KeyPair generateKeyPair;

    private PublicKeyRegistry publicKeyRegistry;

    public RSAKeystore() {
    }

    public RSAKeystore(PublicKeyRegistry publicKeyRegistry) {
        this.publicKeyRegistry = publicKeyRegistry;
    }

    @Override
    public PublicKey getPublicKey() {
        return generateKeyPair.getPublic();
    }

    @Override
    public PublicKey getAppPublicKey(String applicationName, String instanceId) {
        if (publicKeyRegistry == null) {
            LOG.warn("No PublicKeyRegistry registered");
            return null;
        }
        return publicKeyRegistry.getPublicKey(applicationName, instanceId);
    }

    @Override
    public PrivateKey getPrivateKey() {
        return generateKeyPair.getPrivate();
    }

    public void init() {
        generateKeyPair = RsaProvider.generateKeyPair(KEY_SIZE_IN_BITS);
    }

}
