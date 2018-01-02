package com.boot.jwt.core.key;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;

public class JwtSigningKeyResolver extends SigningKeyResolverAdapter {

    private static final Logger LOG = LoggerFactory.getLogger(JwtSigningKeyResolver.class);

    private Keystore keystore;

    public JwtSigningKeyResolver(Keystore keystore) {
        this.keystore = keystore;
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        String instanceId = claims.getId();
        String appName = claims.getIssuer();
        LOG.debug("Resolving public key for app {} -> instance id {}", appName, instanceId);
        return keystore.getAppPublicKey(new AppMetadata(appName, instanceId));
    }
}
