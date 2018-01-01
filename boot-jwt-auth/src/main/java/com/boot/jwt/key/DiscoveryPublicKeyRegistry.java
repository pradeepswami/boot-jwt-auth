package com.boot.jwt.key;

import com.boot.jwt.core.key.PublicKeyRegistry;
import io.jsonwebtoken.impl.TextCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Optional;

public class DiscoveryPublicKeyRegistry implements PublicKeyRegistry {

    private static final Logger LOG = LoggerFactory.getLogger(DiscoveryPublicKeyRegistry.class);

    public static final String JWT_PUBLIC_KEY = "jwt-public-core";
    private DiscoveryClient discoveryClient;

    public DiscoveryPublicKeyRegistry(DiscoveryClient discoveryClient) {
        this.discoveryClient = discoveryClient;
    }

    @Override
    public PublicKey getPublicKey(String applicationId, String instanceId) {
        LOG.info("Getting public core for {}, Instance id -> {}", applicationId, instanceId);
        List<ServiceInstance> instances = discoveryClient.getInstances(applicationId);
        PublicKey publicKey = null;
        Optional<ServiceInstance> firstItem = instances.stream()
                .filter(ins -> ins.getServiceId().equalsIgnoreCase(instanceId))
                .findFirst();

        if (firstItem.isPresent()) {
            String base64URLKey = firstItem.get().getMetadata().get(JWT_PUBLIC_KEY);
            byte[] byteKey = TextCodec.BASE64URL.decode(base64URLKey);
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            try {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                publicKey = kf.generatePublic(X509publicKey);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                LOG.error("Unable to extract public key for " + applicationId + " - " + applicationId, e);
            }
        }

        return publicKey;
    }
}
