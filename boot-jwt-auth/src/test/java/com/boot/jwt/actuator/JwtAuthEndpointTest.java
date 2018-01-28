package com.boot.jwt.actuator;

import com.boot.jwt.core.key.Keystore;
import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.security.PublicKey;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class JwtAuthEndpointTest {


    private PublicKey publicKey = RsaProvider.generateKeyPair().getPublic();


    @Mock
    private Keystore mockKeystore;


    @Test
    public void getBase64UrlPublicKey_typical() throws Exception {
        when(mockKeystore.getPublicKey()).thenReturn(publicKey);
        JwtAuthEndpoint jwtAuthEndpoint = new JwtAuthEndpoint(mockKeystore);

        String base64UrlPublicKey = jwtAuthEndpoint.getBase64UrlPublicKey();

        assertThat(base64UrlPublicKey.length() > 1, is(true));
    }

    @Test
    public void getBase64UrlPublicKey_exception() throws Exception {
        when(mockKeystore.getPublicKey()).thenThrow(new RuntimeException());
        JwtAuthEndpoint jwtAuthEndpoint = new JwtAuthEndpoint(mockKeystore);

        String base64UrlPublicKey = jwtAuthEndpoint.getBase64UrlPublicKey();

        assertThat(base64UrlPublicKey.length() > 1, is(false));
    }


    @Test
    public void getBase64UrlPublicKey_key_is_null() throws Exception {
        when(mockKeystore.getPublicKey()).thenReturn(null);
        JwtAuthEndpoint jwtAuthEndpoint = new JwtAuthEndpoint(mockKeystore);

        String base64UrlPublicKey = jwtAuthEndpoint.getBase64UrlPublicKey();

        assertThat(base64UrlPublicKey.length() > 1, is(false));
    }


}