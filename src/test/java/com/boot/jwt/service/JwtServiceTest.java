package com.boot.jwt.service;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.SigningKeyResolver;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

import com.boot.jwt.configuration.JwtAuthProperties;

@RunWith(MockitoJUnitRunner.class)
public class JwtServiceTest {
	@Spy
	private JwtAuthProperties jwtAuthProperties = new JwtAuthProperties();

	@Mock
	private KeyStoreAdapter keyStoreAdapter;

	@InjectMocks
	private JwtService jwtService;

	private static PrivateKey privateKey;
	private static PublicKey publicKey;

	private static String ENCRYPT_STR = "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJzYW1wbGUiLCJpYXQiOjE0ODM3MjAzNDEsImV4cCI6MTQ4MzcyMDQ2MSwic3ViIjoic2FtcGxlIn0.uB2ejOsbGloM7tdBxgKeDIWn8reJN0K8lIeeTedAZ6VieEEq-egrhFJJZjAvbCF98C0f0P6m4NaE2KZLajZmBiI_kfoVIsW7uGNAYvHiQCoCS810EeLvmfrqYOmxzwsihEky98SWR_ryHSeewaRrIqnm7as6MHZoYb9ICU2aBVrt3id7o-y7mMfJX1bXUl6wSlrn5tR82npaUItdppQiYmTCwpDxlMl2DSvlheaqeSAERyyNtrENPX7R7jYvctgnjtnljnlffYO5WfPz5xwj_LuL0_Rtrfz5KZV1OvQvNXaP2HGpHjL2ieGGHshu6txOLVUzaOXScFoAEfDI39-Ykg";

	@BeforeClass
	public static void classSetup() throws Exception {
		extractKey();
	}

	@Before
	public void setup() {
		this.jwtAuthProperties.setAppName("sample");
	}

	@Test
	public void testGenerateTokenAndParse() throws Exception {

		when(keyStoreAdapter.getPrivateKey()).thenReturn(privateKey);
		when(keyStoreAdapter.getSigningKeyResolver()).thenReturn(new SigningKeyResolverTest());
		String tokenStr = jwtService.generateToken();
		Jwt<Header, Claims> jwt = jwtService.paserJwt(tokenStr);
		assertThat(jwt.getBody().getId(), equalTo("sample"));

	}

	@Test(expected = ExpiredJwtException.class)
	public void paserJwt_expiredtoken() throws Exception {
		when(keyStoreAdapter.getSigningKeyResolver()).thenReturn(new SigningKeyResolverTest());
		Jwt<Header, Claims> jwt = jwtService.paserJwt(ENCRYPT_STR);

	}

	private static void extractKey() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException, UnrecoverableKeyException {
		KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
		String pwd = "sample";
		store.load(JwtServiceTest.class.getResourceAsStream("/sample.jks"), pwd.toCharArray());
		privateKey = (PrivateKey) store.getKey("sample", pwd.toCharArray());
		publicKey = store.getCertificate("sample").getPublicKey();
	}

	private static class SigningKeyResolverTest implements SigningKeyResolver {

		@Override
		public Key resolveSigningKey(JwsHeader header, String plaintext) {
			return publicKey;
		}

		@Override
		public Key resolveSigningKey(JwsHeader header, Claims claims) {

			return publicKey;
		}
	}

}
