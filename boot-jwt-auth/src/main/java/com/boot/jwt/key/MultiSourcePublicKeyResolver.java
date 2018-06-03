package com.boot.jwt.key;

import com.boot.jwt.core.PublicKeyNotFoundException;
import com.boot.jwt.core.key.AppMetadata;
import com.boot.jwt.core.key.PublicKeyRegistry;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

import java.security.Key;
import java.util.Map;
import java.util.Objects;

public class MultiSourcePublicKeyResolver extends SigningKeyResolverAdapter {

    private final static Logger LOG = LoggerFactory.getLogger(MultiSourcePublicKeyResolver.class);


    @Autowired
    private ApplicationContext applicationContext;

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        String instanceId = claims.getId();
        String appName = claims.getIssuer();
        AppMetadata appMetadata = new AppMetadata(appName, instanceId);
        PublicKeyRegistry publicKeyRegistry = getPublicKeyRegistry(appMetadata);

        LOG.debug("Resolving public key for app {} -> instance id {}", appName, instanceId);
        return publicKeyRegistry.getPublicKey(appMetadata);
    }


    PublicKeyRegistry getPublicKeyRegistry(AppMetadata appMetadata) {
        Map<String, PublicKeyRegistry> registryMap = this.applicationContext.getBeansOfType(PublicKeyRegistry.class);
        for (Map.Entry<String, PublicKeyRegistry> entry :
                registryMap.entrySet()) {
            if (Objects.nonNull(entry.getValue()) && entry.getValue().hasKey(appMetadata)) {
                return entry.getValue();
            }
        }
        throw new PublicKeyNotFoundException(appMetadata.getAppName(), appMetadata.getInstanceId());
    }
}
