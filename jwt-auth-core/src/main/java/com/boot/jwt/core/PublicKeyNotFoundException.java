package com.boot.jwt.core;

public class PublicKeyNotFoundException extends RuntimeException {
    public PublicKeyNotFoundException(String appName, String instanceId) {
        super("Public core not found for application " + appName + " - " + instanceId);
    }
}
