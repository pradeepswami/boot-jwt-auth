package com.boot.jwt.actuator;

import com.boot.jwt.core.key.Keystore;
import com.google.common.collect.ImmutableMap;
import io.jsonwebtoken.impl.TextCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.endpoint.AbstractEndpoint;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@ConfigurationProperties(prefix = "endpoints.jwtauth")
public class JwtAuthEndpoint extends AbstractEndpoint<List<Map<String, ?>>> {

    private final static Logger LOG = LoggerFactory.getLogger(JwtAuthEndpoint.class);

    private Keystore keystore;

    public JwtAuthEndpoint(Keystore keystore) {
        super("jwtauth");
        this.keystore = keystore;
    }

    @Override
    public List<Map<String, ?>> invoke() {
        List<Map<String, ?>> mapList = new ArrayList<>();
        mapList.add(ImmutableMap.of("public-key", getBase64UrlPublicKey()));
        return mapList;
    }

    protected String getBase64UrlPublicKey() {
        Key publicKey = null;
        try {
            publicKey = keystore.getPublicKey();
        } catch (Exception e) {
            LOG.warn("Exception retrieving public key from keystore. ", e);
            return "";
        }

        if (Objects.isNull(publicKey)) {
            LOG.warn("public i");
            return "";
        }

        return TextCodec.BASE64URL.encode(publicKey.getEncoded());
    }
}
