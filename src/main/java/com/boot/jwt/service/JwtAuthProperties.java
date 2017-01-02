package com.boot.jwt.service;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

@ConfigurationProperties(prefix = "auth.jwt")
public class JwtAuthProperties {

	private String appName;
	private Resource keyStore;
	private String storePassword;
	private String keyPassword;
	private String alias;
	private String algo;
	private int expSeconds = 120;
	private Map<String, String> trustedAppKeys = new HashMap<String, String>();

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

	public String getAlgo() {
		return algo;
	}

	public void setAlgo(String algo) {
		this.algo = algo;
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

}
