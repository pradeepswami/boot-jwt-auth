package com.boot.jwt.service;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SigningKeyResolver;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.core.io.ClassPathResource;

import com.boot.jwt.service.JwtAuthProperties;
import com.boot.jwt.service.KeyStoreAdapter;
import com.google.common.collect.ImmutableMap;

@RunWith(MockitoJUnitRunner.class)
public class KeyStoreAdapterTest {
	@Spy
	private JwtAuthProperties jwtConfiguration = new JwtAuthProperties();

	@InjectMocks
	private KeyStoreAdapter testObject;

	@Test
	public void testInit() throws Exception {
		Claims claims = Mockito.mock(Claims.class);

		jwtConfiguration.setKeyStore(new ClassPathResource("/sample.jks"));
		jwtConfiguration.setAlias("sample");
		jwtConfiguration.setKeyPassword("sample");
		jwtConfiguration.setStorePassword("sample");
		jwtConfiguration.setTrustedAppKeys(ImmutableMap.of("clientAppId", "sample-client"));
		when(claims.getId()).thenReturn("clientAppId");

		testObject.init();
		SigningKeyResolver signingKeyResolver = testObject.getSigningKeyResolver();

		assertNotNull(testObject.getPrivateKey());
		assertNotNull(testObject.getPublicKey());
		assertNotNull(testObject.getAppPublicKey("clientAppId"));
		assertNotNull(signingKeyResolver.resolveSigningKey(null, claims));

	}
}
