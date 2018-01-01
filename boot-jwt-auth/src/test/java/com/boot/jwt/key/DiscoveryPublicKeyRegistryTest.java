package com.boot.jwt.key;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.cloud.client.DefaultServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

@RunWith(MockitoJUnitRunner.class)
public class DiscoveryPublicKeyRegistryTest {

    public static final String APP_ID = "appId";
    public static final String INSTANCE_ID = "instanceId";
    @Mock
    private DiscoveryClient mockDiscoveryClient;

    private DiscoveryPublicKeyRegistry discoveryPublicKeyRegistry;

    @Before
    public void setUp() throws Exception {
        this.discoveryPublicKeyRegistry = new DiscoveryPublicKeyRegistry(mockDiscoveryClient);
    }

    @Test
    public void getPublicKey_typical() throws Exception {
        Mockito.when(mockDiscoveryClient.getInstances(APP_ID)).thenReturn(Arrays.asList(createInstance()));

        PublicKey rstKey = discoveryPublicKeyRegistry.getPublicKey(APP_ID, INSTANCE_ID);

        assertThat(rstKey, notNullValue());
        assertThat(rstKey.getAlgorithm(), equalTo("RSA"));
    }

    @Test
    public void getPublicKey_emptyInstance() throws Exception {
        Mockito.when(mockDiscoveryClient.getInstances(APP_ID)).thenReturn(Collections.EMPTY_LIST);

        PublicKey rstKey = discoveryPublicKeyRegistry.getPublicKey(APP_ID, INSTANCE_ID);

        assertThat(rstKey, nullValue());
    }

    private DefaultServiceInstance createInstance() {
        DefaultServiceInstance serviceInstance = new DefaultServiceInstance(INSTANCE_ID, "hostname", 0, false);
        serviceInstance.getMetadata().put(DiscoveryPublicKeyRegistry.JWT_PUBLIC_KEY, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiVlUtnSb-YZiJM5i934OwcioJsr5zHuKMeOfr9jewcfPXzIk0craB2hwrXilnXisAlduVSBIW-pn687zn_QbN7cdAvUU1a94tW8fQJCB8fjWxVyMYsKqB1XRsudAcxJFVPSkNddYH-llO8OQrjroyn0DOXmXlwit9u2xgXOc7idp9A7cpqAdKv6BPK-SoIaEmffOx5_zOzJfsGPtUx_4lIfoX75h_ogJSKjmdFi-Eq9UnPEFiMO_9GlLAb6VYFCkrZPrlRIlKMEiXs0phlxNQuOrXq5Ukf4OKzuNnn1qHb_5sPGsZpOGva6FPTWnTV4zdv1wB8n60mlqWrj3vay0BQIDAQAB");
        return serviceInstance;
    }

}