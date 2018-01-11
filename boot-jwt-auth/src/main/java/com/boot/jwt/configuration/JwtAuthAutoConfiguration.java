package com.boot.jwt.configuration;

import com.boot.jwt.core.JJwtServiceImpl;
import com.boot.jwt.core.JwtService;
import com.boot.jwt.core.key.*;
import com.boot.jwt.security.RestClientAuthInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ResourceCondition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.IOException;

@Configuration
public class JwtAuthAutoConfiguration {

    @Autowired
    private JwtAuthProperties jwtAuthProperties;

    @Bean
    @ConditionalOnMissingBean(JwtService.class)
    public JwtService jwtService(Keystore keystore) {

        return JJwtServiceImpl.JwtServiceBuilder.getInstance()
                .appName(jwtAuthProperties.getAppName())
                .instanceId(jwtAuthProperties.getInstanceId())
                .algo(jwtAuthProperties.getAlgo().name())
                .keystore(keystore)
                .signingKeyResolver(new JwtSigningKeyResolver(keystore))
                .build();
    }

    @Configuration
    @ConditionalOnProperty(value = "jwt.auth.algo", havingValue = "HMAC", matchIfMissing = true)
    public static class HMACConfiguration {

        @Autowired
        private JwtAuthProperties jwtAuthProperties;


        @Bean
        @ConditionalOnMissingBean(Keystore.class)
        public Keystore hmacKeystore() throws IOException {
            return new HMACKeystore(jwtAuthProperties.getSecret());
        }
    }

    @Configuration
    @ConditionalOnProperty(value = "jwt.auth.algo", havingValue = "RSA")
    public static class RSAConfiguration {

        @Autowired
        private JwtAuthProperties jwtAuthProperties;


        @Bean
        @ConditionalOnMissingBean(Keystore.class)
        @Conditional(JKSAvailableCondition.class)
        public Keystore jksKeystore() throws IOException {

            Resource keyStoreResource = jwtAuthProperties.getKeyStore();

            JksKeystore jksKeystore = new JksKeystore(keyStoreResource.getInputStream(),
                    jwtAuthProperties.getStorePasswordChar(),
                    jwtAuthProperties.getKeyPasswordChar(),
                    jwtAuthProperties.getAlias());

            JksPublicKeyRegistry registry = new JksPublicKeyRegistry(keyStoreResource.getInputStream(),
                    jwtAuthProperties.getStorePasswordChar(),
                    jwtAuthProperties.getTrustedAppKeys());
            jksKeystore.setPublicKeyRegistry(registry);

            return jksKeystore;
        }


    }

    @Bean
    public RestClientAuthInterceptor restClientAuthInterceptor() {
        return new RestClientAuthInterceptor();
    }

    public static class JKSAvailableCondition extends ResourceCondition {

        protected JKSAvailableCondition() {
            super("JWTAuth", "jwt.auth", "keyStore", new String[]{});
        }
    }


}
