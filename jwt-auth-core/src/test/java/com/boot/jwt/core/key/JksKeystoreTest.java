package com.boot.jwt.core.key;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class JksKeystoreTest {
    public static final String SAMPLE_JKS = "/sample.jks";

    public static final char[] STORE_PASSWORD = "sample".toCharArray();
    public static final String SAMPLE = "sample";
    public static final String APP_ID = "appId";
    private JksKeystore testObject;

    @Mock
    private PublicKeyRegistry mockPublicRegistry;


    @Before
    public void setUp() throws Exception {
        testObject = new JksKeystore(this.getClass().getResourceAsStream(SAMPLE_JKS), STORE_PASSWORD, STORE_PASSWORD, SAMPLE);
    }

    @Test
    public void getPublicKey_test() throws Exception {
        assertTrue(testObject.getPublicKey() instanceof PublicKey);
    }

    @Test
    public void getPrivateKey_test() throws Exception {
        assertTrue(testObject.getPrivateKey() instanceof PrivateKey);
    }


}