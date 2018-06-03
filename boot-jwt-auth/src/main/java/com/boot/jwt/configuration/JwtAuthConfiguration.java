package com.boot.jwt.configuration;

import com.boot.jwt.actuator.JwtAuthEndpoint;
import com.boot.jwt.configuration.condition.JwtJksAvailableCondition;
import com.boot.jwt.core.JJwtServiceImpl;
import com.boot.jwt.core.JwtService;
import com.boot.jwt.core.key.*;
import com.boot.jwt.key.MultiSourcePublicKeyResolver;
import io.jsonwebtoken.SigningKeyResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import java.io.IOException;

@Configuration
public class JwtAuthConfiguration {

    @ConditionalOnMissingBean(JwtService.class)
    @Bean
    public JwtService jwtService(Keystore keystore, JwtAuthProperties jwtAuthProperties) {

        return JJwtServiceImpl.JwtServiceBuilder.getInstance()
                .appName(jwtAuthProperties.getAppName())
                .instanceId(jwtAuthProperties.getInstanceId())
                .algo(jwtAuthProperties.getAlgo().name())
                .keystore(keystore)
                .signingKeyResolver(signingKeyResolver())
                .build();
    }

    @Bean
    public SigningKeyResolver signingKeyResolver() {
        return new MultiSourcePublicKeyResolver();
    }

    @Configuration
    @ConditionalOnProperty(prefix = "jwt.auth", name = "algo", havingValue = "HMAC")
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
    @ConditionalOnProperty(prefix = "jwt.auth", name = "algo", havingValue = "RSA")
    public static class RSAConfiguration {

        @Bean
        @ConditionalOnMissingBean(Keystore.class)
        @Conditional(JwtJksAvailableCondition.class)
        public Keystore jksKeystore(JwtAuthProperties jwtAuthProperties) throws IOException {

            Resource keyStoreResource = jwtAuthProperties.getKeyStore();

            JksKeystore jksKeystore = new JksKeystore(keyStoreResource.getInputStream(),
                    jwtAuthProperties.getStorePasswordChar(),
                    jwtAuthProperties.getKeyPasswordChar(),
                    jwtAuthProperties.getAlias());

            return jksKeystore;
        }

        @Bean
        @Conditional(JwtJksAvailableCondition.class)
        public PublicKeyRegistry jksPublicKeyRegistry(JwtAuthProperties jwtAuthProperties) throws IOException {
            Resource keyStoreResource = jwtAuthProperties.getKeyStore();
            JksPublicKeyRegistry jksKeystore = new JksPublicKeyRegistry(keyStoreResource.getInputStream(),
                    jwtAuthProperties.getStorePasswordChar(),
                    jwtAuthProperties.getTrustedAppKeys());
            return jksKeystore;
        }
    }

    @Bean
    public JwtAuthEndpoint jwtAuthEndpoint(Keystore keystore) {
        return new JwtAuthEndpoint(keystore);
    }


    @EnableWebSecurity
    @ConditionalOnProperty(prefix = "jwt.auth", name = "mode", havingValue = "server", matchIfMissing = true)
    public static class JwtSecurityConfigAdapterImpl extends JwtSecurityConfigAdapter {

        @Autowired
        @Override
        public void setJwtService(JwtService jwtService) {
            super.setJwtService(jwtService);
        }
    }


}
