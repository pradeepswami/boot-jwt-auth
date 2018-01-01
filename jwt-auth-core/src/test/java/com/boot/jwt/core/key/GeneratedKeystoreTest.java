package com.boot.jwt.core.key;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.PublicKey;

public class GeneratedKeystoreTest {

    private GenratedRSAKeystore GenratedRSAKeystore;


    @Before
    public void setUp() throws Exception {
        GenratedRSAKeystore = new GenratedRSAKeystore();
        GenratedRSAKeystore.init();
    }

    @Test
    public void getPublicKey_typical() throws Exception {
        PublicKey publicKey = GenratedRSAKeystore.getPublicKey();
        Assert.assertNotNull(publicKey);
    }

}