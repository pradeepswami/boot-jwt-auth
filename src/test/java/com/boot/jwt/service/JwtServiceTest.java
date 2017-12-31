package com.boot.jwt.service;

import com.boot.jwt.key.HMACKeystore;
import com.boot.jwt.key.Keystore;
import com.google.common.collect.ImmutableMap;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.TextCodec;
import io.jsonwebtoken.impl.crypto.MacProvider;
import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class JwtServiceTest {

    public static final String TEST_SECRET = "secret2";
    public static final String TEST_SECRET3 = "secret3";

    public static final String HMAC = "hmac";
    public static final String APP_NAME = "testApp";
    public static final String RANDOM_VALUE = "random-value1";
    public static final String KEY = "key1";

    public static final String JWT_TOKEN_EXPIRED_HMAC = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0QXBwIiwianRpIjoidGVzdEFwcDEiLCJpYXQiOjE1MTQ3MzIxNDcsImV4cCI6MTUxNDczMjI2Nywic3ViIjoidGVzdEFwcCIsImtleTEiOiJyYW5kb20tdmFsdWUxIn0.R0_9n-ErS4Xa24R31NTGKWdINBXaJ61IV8QUKE7ADdY";
    public static final String JWT_TOKEN_EXPIRED_RSA = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0QXBwIiwianRpIjoidGVzdEFwcDEiLCJpYXQiOjE1MTQ2OTU3ODYsImV4cCI6MTUxNDY5NTkwNiwic3ViIjoidGVzdEFwcCIsImtleTEiOiJyYW5kb20tdmFsdWUxIn0.nA2xfY1AKRuSttFqaVSVYZ3yhuJ1K3pee1UHbuybIRW7lLHNzRcrIeA82Gafu0cXi4Xp5y5g_2AamoNaErzcsSGwqvZt7c--egD4WIRdPBixStCgm1pTiZYAqampxPSMa_5EOWK1KM5MUJD09X-grj5UQX2WiuNxgghFdp9xs_A2ASQZRLz11QrqWtRFGJ4eXJXUSyF51VpPbNR8pmfFcVNTJuC9_573atsDumBmc0ae296Gl7QDtPd_yjPnUQ148xNRKxVqYWp5e8IgTzX9NXvUXafURyU4nJz-n8LbU6_SGktlPSWvu8jlJBZiyxI0vmxwhMjPKzvE_F1d3ecvFA";

    public static final String RSA = "rsa";
    public static final int KEY_SIZE_IN_BITS = 2048;
    public static final KeyPair KEY_PAIR = RsaProvider.generateKeyPair(KEY_SIZE_IN_BITS);
    public static final KeyPair KEY_PAIR2 = RsaProvider.generateKeyPair(KEY_SIZE_IN_BITS);

    public static final String HMAC_KEY_1 = "XqLe/s1jnJBLnz8HoiBelfbY9H+qG0jouds5cAEKucc=";
    public static final String HMAC_KEY_2 = "9AL9nBa9dDP65owuWcfKNIVjWctpcZU1Oj1HlUsUGH8=";


    @Mock
    private Keystore mockKeystore;

    @Mock
    private SigningKeyResolver mockKeyResolver;

    @Test
    public void generateToken_typicalHMAC() throws Exception {

        HMACKeystore hmacKeystore = new HMACKeystore(HMAC_KEY_1);
        JwtService jwtService = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(HMAC)
                .keystore(hmacKeystore)
                .build();

        String rstToken = jwtService.generateToken(ImmutableMap.of(KEY, RANDOM_VALUE));
        System.out.println(rstToken);
        assertThat(rstToken, notNullValue());
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[0]), containsString("HS256"));
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[1]), containsString(APP_NAME));
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[1]), containsString(APP_NAME + 1));
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[1]), containsString(RANDOM_VALUE));
    }

    @Test(expected = NullPointerException.class)
    public void jwtSericeBuilder_noapplicationName() throws Exception {

        JwtService.JwtServiceBuilder.getInstance()
                .instanceId(APP_NAME + 1)
                .algo(HMAC)
                .build();

    }

    @Test(expected = ExpiredJwtException.class)
    public void paserJwt_Expired_hmac() throws Exception {

        when(mockKeyResolver.resolveSigningKey(Matchers.any(JwsHeader.class), Matchers.any(Claims.class))).thenReturn(createHmacKey(HMAC_KEY_1));
        JwtService jwtService = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(HMAC)
                .signingKeyResolver(mockKeyResolver)
                .build();

        jwtService.paserJwt(JWT_TOKEN_EXPIRED_HMAC);
    }


    @Test
    public void paserJwt_typicalHMAC() throws Exception {

        HMACKeystore hmacKeystore = new HMACKeystore(HMAC_KEY_1);
        when(mockKeyResolver.resolveSigningKey(Matchers.any(JwsHeader.class), Matchers.any(Claims.class))).thenReturn(createHmacKey(HMAC_KEY_1));


        JwtService jwtService = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(HMAC)
                .keystore(hmacKeystore)
                .build();
        String generatedToken = jwtService.generateToken(ImmutableMap.of(KEY, RANDOM_VALUE));


        Jwt<Header, Claims> headerClaimsJwt = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(HMAC)
                .signingKeyResolver(mockKeyResolver)
                .build()
                .paserJwt(generatedToken);


        assertThat(headerClaimsJwt.getHeader().get(JwsHeader.ALGORITHM), equalTo("HS256"));
        assertThat(headerClaimsJwt.getBody().getId(), equalTo(APP_NAME + 1));
        assertThat(headerClaimsJwt.getBody().getIssuer(), equalTo(APP_NAME));
        assertThat(headerClaimsJwt.getBody().get(KEY, String.class), equalTo(RANDOM_VALUE));
    }

    @Test(expected = SignatureException.class)
    public void paserJwt_wrongSecretHMAC() throws Exception {
        HMACKeystore hmacKeystore = new HMACKeystore(HMAC_KEY_1);
        when(mockKeyResolver.resolveSigningKey(Matchers.any(JwsHeader.class), Matchers.any(Claims.class))).thenReturn(createHmacKey(HMAC_KEY_2));
        JwtService jwtService = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(HMAC)
                .keystore(hmacKeystore)
                .build();
        String generatedToken = jwtService.generateToken(ImmutableMap.of(KEY, RANDOM_VALUE));


        Jwt<Header, Claims> headerClaimsJwt = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(HMAC)
                .signingKeyResolver(mockKeyResolver)
                .build()
                .paserJwt(generatedToken);
    }


    @Test
    public void generateToken_typicalRSA() throws Exception {
        when(mockKeystore.getPrivateKey()).thenReturn(KEY_PAIR.getPrivate());
        JwtService jwtService = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(RSA)
                .keystore(mockKeystore)
                .build();

        String rstToken = jwtService.generateToken(ImmutableMap.of(KEY, RANDOM_VALUE));

        System.out.println(rstToken);
        assertThat(rstToken, notNullValue());
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[0]), containsString("RS256"));
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[1]), containsString(APP_NAME));
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[1]), containsString(APP_NAME + 1));
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[1]), containsString(RANDOM_VALUE));
    }

    @Test(expected = SignatureException.class)
    public void paserJwt_ExpiredRSA() throws Exception {
        when(mockKeyResolver.resolveSigningKey(Matchers.any(JwsHeader.class), Matchers.any(Claims.class))).thenReturn(KEY_PAIR.getPublic());
        JwtService jwtService = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(RSA)
                .signingKeyResolver(mockKeyResolver)
                .build();

        Jwt<Header, Claims> claimsJwt = jwtService.paserJwt(JWT_TOKEN_EXPIRED_RSA);
    }


    @Test
    public void paserJwt_typicalRSA() throws Exception {

        when(mockKeystore.getPrivateKey()).thenReturn(KEY_PAIR.getPrivate());
        when(mockKeyResolver.resolveSigningKey(Matchers.any(JwsHeader.class), Matchers.any(Claims.class))).thenReturn(KEY_PAIR.getPublic());


        JwtService jwtService = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(RSA)
                .keystore(mockKeystore)
                .build();
        String generatedToken = jwtService.generateToken(ImmutableMap.of(KEY, RANDOM_VALUE));


        Jwt<Header, Claims> headerClaimsJwt = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(RSA)
                .signingKeyResolver(mockKeyResolver)
                .build()
                .paserJwt(generatedToken);


        assertThat(headerClaimsJwt.getHeader().get(JwsHeader.ALGORITHM), equalTo("RS256"));
        assertThat(headerClaimsJwt.getBody().getId(), equalTo(APP_NAME + 1));
        assertThat(headerClaimsJwt.getBody().getIssuer(), equalTo(APP_NAME));
        assertThat(headerClaimsJwt.getBody().get(KEY, String.class), equalTo(RANDOM_VALUE));
    }

    @Test(expected = SignatureException.class)
    public void paserJwt_wrongPublicKeyRSA() throws Exception {

        when(mockKeystore.getPrivateKey()).thenReturn(KEY_PAIR.getPrivate());
        when(mockKeyResolver.resolveSigningKey(Matchers.any(JwsHeader.class), Matchers.any(Claims.class))).thenReturn(KEY_PAIR2.getPublic());


        JwtService jwtService = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(RSA)
                .keystore(mockKeystore)
                .build();
        String generatedToken = jwtService.generateToken(ImmutableMap.of(KEY, RANDOM_VALUE));


        JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(RSA)
                .signingKeyResolver(mockKeyResolver)
                .build()
                .paserJwt(generatedToken);

    }


    private Key createHmacKey(String base64Key) {
        return new SecretKeySpec(TextCodec.BASE64.decode(base64Key), SignatureAlgorithm.HS256.getJcaName());
    }


    @Test
    public void generateBase64Key() {
        SecretKey secretKey = MacProvider.generateKey(SignatureAlgorithm.HS256);
        String base64Key = TextCodec.BASE64.encode(secretKey.getEncoded());
        System.out.println(base64Key);


    }

}
