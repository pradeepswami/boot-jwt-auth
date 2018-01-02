package com.boot.jwt.core.key;

import java.security.PublicKey;

public interface PublicKeyRegistry {

    PublicKey getPublicKey(AppMetadata appMetadata);
}
