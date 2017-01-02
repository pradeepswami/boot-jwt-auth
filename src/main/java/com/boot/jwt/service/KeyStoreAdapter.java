package com.boot.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.SigningKeyResolverAdapter;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class KeyStoreAdapter {

	private final static Logger LOG = LoggerFactory.getLogger(KeyStoreAdapter.class);

	@Autowired
	private JwtAuthProperties jwtAuthProperties;

	private PrivateKey privateKey;
	private PublicKey publicKey;
	private Map<String, PublicKey> keyMap = new HashMap<String, PublicKey>();

	private final SigningKeyResolver signingKeyResolver = new SigningKeyResolverAdapter() {

		@Override
		public Key resolveSigningKey(JwsHeader header, Claims claims) {

			String appId = claims.getId();
			if (StringUtils.isBlank(appId)) {
				throw new IllegalArgumentException("Missing Id in JWT");
			}
			Key appPublicKey = getAppPublicKey(appId);
			if (appPublicKey == null) {
				throw new RuntimeException("No public key found for appId " + appId);
			}
			return appPublicKey;
		}

	};

	public void init() {

		try {
			InputStream jks = jwtAuthProperties.getKeyStore().getInputStream();
			KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
			store.load(jks, jwtAuthProperties.getStorePasswordChar());
			privateKey = (PrivateKey) store
					.getKey(jwtAuthProperties.getAlias(), jwtAuthProperties.getKeyPasswordChar());
			publicKey = store.getCertificate(jwtAuthProperties.getAlias()).getPublicKey();
			for (Map.Entry<String, String> entry : jwtAuthProperties.getTrustedAppKeys().entrySet()) {
				Certificate certificate = store.getCertificate(entry.getValue());
				if (certificate == null) {
					LOG.warn("No certificate found for appId {}, alias {}", entry.getKey(), entry.getValue());
				}
				PublicKey pk = certificate.getPublicKey();
				keyMap.put(entry.getKey(), pk);
			}

		} catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| UnrecoverableKeyException e) {
			throw new RuntimeException("Exception loading keys from jks store", e);
		}
	}

	public Key getPublicKey() {
		return publicKey;
	}

	Key getPrivateKey() {
		return privateKey;
	}

	Key getAppPublicKey(String appId) {
		return keyMap.get(appId);

	}

	public SigningKeyResolver getSigningKeyResolver() {
		return signingKeyResolver;
	}

}
