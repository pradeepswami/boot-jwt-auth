package com.boot.jwt.core.key;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.PublicKey;

public class GeneratedKeystoreTest {

    private com.boot.jwt.core.key.RSAKeystore RSAKeystore;


    @Before
    public void setUp() throws Exception {
        RSAKeystore = new RSAKeystore();
        RSAKeystore.init();
    }

    @Test
    public void getPublicKey_typical() throws Exception {
        PublicKey publicKey = RSAKeystore.getPublicKey();
        Assert.assertNotNull(publicKey);
    }

}