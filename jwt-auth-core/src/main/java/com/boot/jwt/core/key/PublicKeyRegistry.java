package com.boot.jwt.core.key;

import java.security.PublicKey;

public interface PublicKeyRegistry {

    PublicKey getPublicKey(String applicationId, String instanceId);
}