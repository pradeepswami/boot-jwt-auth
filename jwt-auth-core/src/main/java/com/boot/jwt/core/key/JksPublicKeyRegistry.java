package com.boot.jwt.core.key;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

public class JksPublicKeyRegistry implements PublicKeyRegistry {

    private static final Logger LOG = LoggerFactory.getLogger(JksPublicKeyRegistry.class);

    private static final Map<String, PublicKey> KEY_MAP = new HashMap<>();

    public JksPublicKeyRegistry(InputStream jks, char[] storePassword, Map<String, String> aliasMap) {
        LOG.info("Constructing jks public key registry with aliasMap {}", aliasMap);
        try {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(jks, storePassword);

            for (Map.Entry<String, String> entry : aliasMap.entrySet()) {
                Certificate certificate = store.getCertificate(entry.getValue());
                if (certificate == null) {
                    LOG.warn("No certificate found for appInstanceId {}, alias {}", entry.getKey(), entry.getValue());
                    continue;
                }
                PublicKey pk = certificate.getPublicKey();
                KEY_MAP.put(StringUtils.lowerCase(entry.getKey()), pk);
            }
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException("Exception loading public keys from jks store", e);
        }

    }

    @Override
    public PublicKey getPublicKey(AppMetadata appMetadata) {
        PublicKey publicKey = KEY_MAP.get(StringUtils.lowerCase(appMetadata.getInstanceId()));
        return (publicKey != null ? publicKey :
                KEY_MAP.get(StringUtils.lowerCase(appMetadata.getAppName())));

    }

    @Override
    public boolean hasKey(AppMetadata appMetadata) {
        return KEY_MAP.containsKey(StringUtils.lowerCase(appMetadata.getInstanceId()))
                || KEY_MAP.containsKey(StringUtils.lowerCase(appMetadata.getAppName()));
    }
}
