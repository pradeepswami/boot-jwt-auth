package com.boot.jwt.service;

public class PublicKeyNotFound extends RuntimeException {
    public PublicKeyNotFound(String appName, String instanceId) {
        super("Public key not found for application " + appName + " - " + instanceId);
    }
}
