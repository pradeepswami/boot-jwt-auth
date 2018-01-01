package com.boot.jwt.core.key;

import com.google.common.collect.ImmutableMap;
import org.junit.Test;

import java.security.PublicKey;

import static com.boot.jwt.core.key.JksKeystoreTest.SAMPLE_JKS;
import static com.boot.jwt.core.key.JksKeystoreTest.STORE_PASSWORD;
import static org.junit.Assert.assertTrue;

public class JksPublicKeyRegistryTest {

    public static final String APP_INSTANCE_ID = "appInstanceId";
    public static final String SAMPLE_ALIAS = "sample";
    private JksPublicKeyRegistry testObject;


    @Test
    public void getPublicKey_test() throws Exception {
        testObject = new JksPublicKeyRegistry(this.getClass().getResourceAsStream(SAMPLE_JKS), STORE_PASSWORD, ImmutableMap.of(APP_INSTANCE_ID, SAMPLE_ALIAS));
        PublicKey appPublicKey = testObject.getPublicKey(APP_INSTANCE_ID);

        assertTrue(appPublicKey instanceof PublicKey);

    }

}