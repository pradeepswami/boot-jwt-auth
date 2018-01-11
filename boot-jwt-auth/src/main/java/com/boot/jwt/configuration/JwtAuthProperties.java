package com.boot.jwt.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@ConfigurationProperties(prefix = "jwt.auth")
public class JwtAuthProperties {

    public enum Algo {RSA, HMAC}

    ;

    private String appName;
    private String instanceId;
    private Resource keyStore;
    private String storePassword;
    private String keyPassword;
    private String alias;
    private Algo algo = Algo.HMAC;
    private int expSeconds = 120;
    private boolean enabled = true;
    private List<String> excludePaths = new ArrayList<>();
    private Map<String, String> trustedAppKeys = new HashMap<String, String>();
    private String secret;

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public Resource getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(Resource keyStore) {
        this.keyStore = keyStore;
    }

    public String getStorePassword() {
        return storePassword;
    }

    public char[] getStorePasswordChar() {
        return storePassword.toCharArray();
    }

    public void setStorePassword(String storePassword) {
        this.storePassword = storePassword;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public char[] getKeyPasswordChar() {
        return keyPassword.toCharArray();
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public Map<String, String> getTrustedAppKeys() {
        return trustedAppKeys;
    }

    public String getTrustedAlias(String appId) {
        return trustedAppKeys.get(appId);
    }

    public void setTrustedAppKeys(Map<String, String> trustedAppKeys) {
        this.trustedAppKeys = trustedAppKeys;
    }

    public int getExpSeconds() {
        return expSeconds;
    }

    public void setExpSeconds(int expSeconds) {
        this.expSeconds = expSeconds;
    }

    public List<String> getExcludePaths() {
        return excludePaths;
    }

    public void setExcludePaths(List<String> excludePaths) {
        this.excludePaths = excludePaths;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getInstanceId() {
        return instanceId;
    }

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    public Algo getAlgo() {
        return algo;
    }

    public void setAlgo(Algo algo) {
        this.algo = algo;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }
}
