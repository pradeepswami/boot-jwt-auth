package com.boot.jwt.service;

import com.boot.jwt.key.Keystore;

public class JwtAuthProperties {

    private String appName;
    private int expSeconds = 120;
    private String algo = "RSA";
    private Keystore keystore;


    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public int getExpSeconds() {
        return expSeconds;
    }

    public void setExpSeconds(int expSeconds) {
        this.expSeconds = expSeconds;
    }

    public String getAlgo() {
        return algo;
    }

    public void setAlgo(String algo) {
        this.algo = algo;
    }

    public Keystore getKeystore() {
        return keystore;
    }

    public void setKeystore(Keystore keystore) {
        this.keystore = keystore;
    }
}
