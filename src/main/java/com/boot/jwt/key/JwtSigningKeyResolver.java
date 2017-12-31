package com.boot.jwt.key;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;

import java.security.Key;

public class JwtSigningKeyResolver extends SigningKeyResolverAdapter {

    private Keystore keystore;

    public JwtSigningKeyResolver(Keystore keystore) {
        this.keystore = keystore;
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        String instanceId = claims.getId();
        String appName = claims.getIssuer();
        return keystore.getAppPublicKey(appName, instanceId);
    }
}
