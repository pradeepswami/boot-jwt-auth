package com.boot.jwt.service;

import com.boot.jwt.key.HMACKeystore;
import com.boot.jwt.key.Keystore;
import com.google.common.collect.ImmutableMap;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.impl.TextCodec;
import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.security.KeyPair;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class JwtServiceTest {

    public static final String TEST_SECRET = "secret2";
    public static final String HMAC = "hmac";
    public static final String APP_NAME = "testApp";
    public static final String RANDOM_VALUE = "random-value1";
    public static final String KEY = "key1";

    public static final String JWT_TOKEN_EXPIRED_HMAC = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0QXBwIiwianRpIjoidGVzdEFwcDEiLCJpYXQiOjE1MTQ2OTM5MzUsImV4cCI6MTUxNDY5NDA1NSwic3ViIjoidGVzdEFwcCIsImtleTEiOiJyYW5kb20tdmFsdWUxIn0.3GyxIIW6bad3nIdSiAGNFbCgSD4BBBRrsqWu7MBuOhw";
    public static final String JWT_TOKEN_EXPIRED_RSA = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0QXBwIiwianRpIjoidGVzdEFwcDEiLCJpYXQiOjE1MTQ2OTU3ODYsImV4cCI6MTUxNDY5NTkwNiwic3ViIjoidGVzdEFwcCIsImtleTEiOiJyYW5kb20tdmFsdWUxIn0.nA2xfY1AKRuSttFqaVSVYZ3yhuJ1K3pee1UHbuybIRW7lLHNzRcrIeA82Gafu0cXi4Xp5y5g_2AamoNaErzcsSGwqvZt7c--egD4WIRdPBixStCgm1pTiZYAqampxPSMa_5EOWK1KM5MUJD09X-grj5UQX2WiuNxgghFdp9xs_A2ASQZRLz11QrqWtRFGJ4eXJXUSyF51VpPbNR8pmfFcVNTJuC9_573atsDumBmc0ae296Gl7QDtPd_yjPnUQ148xNRKxVqYWp5e8IgTzX9NXvUXafURyU4nJz-n8LbU6_SGktlPSWvu8jlJBZiyxI0vmxwhMjPKzvE_F1d3ecvFA";

    public static final String RSA = "rsa";
    public static final int KEY_SIZE_IN_BITS = 2048;
    public static final KeyPair KEY_PAIR = RsaProvider.generateKeyPair(KEY_SIZE_IN_BITS);

    @Mock
    private Keystore mockKeystore;


    @Test
    public void generateToken_typicalHMAC() throws Exception {

        HMACKeystore hmacKeystore = new HMACKeystore(TEST_SECRET);
        hmacKeystore.init();
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
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[1]), containsString(APP_NAME));
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[1]), containsString(RANDOM_VALUE));
    }

    @Test(expected = IllegalArgumentException.class)
    public void jwtSericeBuilder_HMAC_nosecret() throws Exception {

        JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(HMAC)
                .build();

    }

    @Test(expected = ExpiredJwtException.class)
    public void paserJwt_Expired() throws Exception {

        JwtService jwtService = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(HMAC)
                .secret(TEST_SECRET)
                .build();

        Jwt<Header, Claims> claimsJwt = jwtService.paserJwt(JWT_TOKEN_EXPIRED_HMAC);
    }


    @Test
    public void paserJwt_typicalHMAC() throws Exception {

        HMACKeystore hmacKeystore = new HMACKeystore(TEST_SECRET);
        hmacKeystore.init();


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
                .keystore(hmacKeystore)
                .build()
                .paserJwt(generatedToken);


        assertThat(headerClaimsJwt.getHeader().get(JwsHeader.ALGORITHM), equalTo("HS256"));
        assertThat(headerClaimsJwt.getBody().getId(), equalTo(APP_NAME + 1));
        assertThat(headerClaimsJwt.getBody().getIssuer(), equalTo(APP_NAME));
        assertThat(headerClaimsJwt.getBody().get(KEY, String.class), equalTo(RANDOM_VALUE));
    }

    @Test(expected = SignatureException.class)
    public void paserJwt_wrongSecretHMAC() throws Exception {

        JwtService jwtService = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(HMAC)
                .secret(TEST_SECRET)
                .build();
        String generatedToken = jwtService.generateToken(ImmutableMap.of(KEY, RANDOM_VALUE));


        Jwt<Header, Claims> headerClaimsJwt = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(HMAC)
                .secret("Secret2")
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
                .secret(TEST_SECRET)
                .keystore(mockKeystore)
                .build();

        String rstToken = jwtService.generateToken(ImmutableMap.of(KEY, RANDOM_VALUE));

        System.out.println(rstToken);
        assertThat(rstToken, notNullValue());
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[0]), containsString("RS256"));
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[1]), containsString(APP_NAME));
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[1]), containsString(APP_NAME));
        assertThat(TextCodec.BASE64URL.decodeToString(rstToken.split("\\.")[1]), containsString(RANDOM_VALUE));
    }

    @Test(expected = ExpiredJwtException.class)
    public void paserJwt_ExpiredRSA() throws Exception {
        when(mockKeystore.getPrivateKey()).thenReturn(KEY_PAIR.getPrivate());
        JwtService jwtService = JwtService.JwtServiceBuilder.getInstance()
                .appName(APP_NAME)
                .instanceId(APP_NAME + 1)
                .algo(RSA)
                .build();

        Jwt<Header, Claims> claimsJwt = jwtService.paserJwt(JWT_TOKEN_EXPIRED_HMAC);
    }


}
