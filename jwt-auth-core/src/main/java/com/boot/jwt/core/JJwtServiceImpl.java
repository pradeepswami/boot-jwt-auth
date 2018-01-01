package com.boot.jwt.core;

import com.boot.jwt.core.key.Keystore;
import io.jsonwebtoken.*;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

public class JJwtServiceImpl implements JwtService {
    private static final Logger LOG = LoggerFactory.getLogger(JJwtServiceImpl.class);
    public static final String RSA = "rsa";
    public static final String HMAC = "hmac";
    private String appName;
    private int expSecond;
    private SignatureAlgorithm algo;
    private Keystore keystore;
    private SigningKeyResolver signingKeyResolver;
    private String instanceId;


    private JJwtServiceImpl() {
    }

    @Override
    public String generateToken(Map<String, String> additionalClaims) {
        Map<String, String> claimToAdd = additionalClaims != null ? additionalClaims : Collections.emptyMap();
        LOG.debug("Generating JWT token with additional claims {}", claimToAdd);
        return createToken(claimToAdd);
    }

    String createToken(Map<String, String> claims) {
        Date now = new Date();
        //@formatter:off
        JwtBuilder jwtBuilder = Jwts.builder()
                .setIssuer(appName)
                .setId(instanceId)
                .setIssuedAt(now)
                .setExpiration(DateUtils.addSeconds(now, expSecond))
                .setSubject(appName);

        //@formatter:on
        for (Map.Entry<String, String> claim : claims.entrySet()) {
            jwtBuilder.claim(claim.getKey(), claim.getValue());
        }
        jwtBuilder.signWith(algo, keystore.getPrivateKey());
        return jwtBuilder.compact();
    }


    @Override
    public Jwt<Header, Claims> paserJwt(String jwt) {
        LOG.debug("Validating JWT token -> {}", jwt);
        JwtParser jwtParser = Jwts.parser();
        jwtParser.setSigningKeyResolver(signingKeyResolver);
        return jwtParser.parse(jwt);
    }

    public static class JwtServiceBuilder {
        private String appName;
        private String instanceId;
        private int expSecond = 120;
        private String algo = RSA;
        private Keystore keystore;
        private SigningKeyResolver signingKeyResolver;

        private JwtServiceBuilder() {
        }

        public static JwtServiceBuilder getInstance() {
            return new JwtServiceBuilder();
        }

        public JwtServiceBuilder appName(String appName) {
            this.appName = appName;
            return this;
        }

        public JwtServiceBuilder expSecond(int expSecond) {
            this.expSecond = expSecond;
            return this;
        }

        public JwtServiceBuilder instanceId(String instanceId) {
            this.instanceId = instanceId;
            return this;
        }


        public JwtServiceBuilder algo(String algo) {
            this.algo = algo;
            return this;
        }

        public JwtServiceBuilder keystore(Keystore keystore) {
            this.keystore = keystore;
            return this;
        }

        public JwtServiceBuilder signingKeyResolver(SigningKeyResolver signingKeyResolver) {
            this.signingKeyResolver = signingKeyResolver;
            return this;
        }

        @Override
        public String toString() {
            return "JwtServiceBuilder{" +
                    "appName='" + appName + '\'' +
                    ", instanceId='" + instanceId + '\'' +
                    ", expSecond=" + expSecond +
                    ", algo='" + algo + '\'' +
                    '}';
        }

        public JJwtServiceImpl build() {
            LOG.debug("Building JJwtServiceImpl with parameters -> {} ", this.toString());
            Objects.requireNonNull(appName, "Application name cannot be null");
            if (StringUtils.isBlank(this.instanceId)) {
                this.instanceId = this.appName;
            }
            JJwtServiceImpl jjwtServiceImpl = new JJwtServiceImpl();
            jjwtServiceImpl.appName = this.appName;
            jjwtServiceImpl.expSecond = this.expSecond;
            jjwtServiceImpl.instanceId = this.instanceId;
            jjwtServiceImpl.keystore = this.keystore;
            jjwtServiceImpl.signingKeyResolver = this.signingKeyResolver;
            if (RSA.equalsIgnoreCase(this.algo)) {
                jjwtServiceImpl.algo = SignatureAlgorithm.RS256;
            } else {
                jjwtServiceImpl.algo = SignatureAlgorithm.HS256;
            }
            return jjwtServiceImpl;
        }
    }
}
