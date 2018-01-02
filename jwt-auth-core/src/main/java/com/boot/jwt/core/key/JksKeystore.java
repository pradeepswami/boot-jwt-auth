package com.boot.jwt.core.key;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

public class JksKeystore implements Keystore {

    private static final Logger LOG = LoggerFactory.getLogger(JksKeystore.class);

    private Key privateKey;
    private Key publicKey;
    private PublicKeyRegistry publicKeyRegistry;

    public JksKeystore(InputStream keystore, char[] storePassword, char[] keyPassword, String alias) {
        LOG.info("Constructing jks keystore with alias {}", alias);
        InputStream jks = keystore;
        try {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(jks, storePassword);
            privateKey = store.getKey(alias, keyPassword);
            publicKey = store.getCertificate(alias).getPublicKey();
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableKeyException e) {
            throw new RuntimeException("Exception loading keys from jks store", e);
        }
    }


    @Override
    public Key getPublicKey() {
        return publicKey;
    }

    @Override
    public Key getAppPublicKey(AppMetadata appMetadata) {
        if (this.publicKeyRegistry == null) {
            LOG.warn("Public Key Registry is not set. Using JksKeystore public key");
            return publicKey;
        }
        return publicKeyRegistry.getPublicKey(appMetadata);
    }

    @Override
    public Key getPrivateKey() {
        return privateKey;
    }

    public void setPublicKeyRegistry(PublicKeyRegistry publicKeyRegistry) {
        this.publicKeyRegistry = publicKeyRegistry;
    }
}
