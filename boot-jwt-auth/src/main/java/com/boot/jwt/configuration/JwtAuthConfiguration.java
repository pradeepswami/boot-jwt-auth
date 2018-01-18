package com.boot.jwt.configuration;

import com.boot.jwt.core.JJwtServiceImpl;
import com.boot.jwt.core.JwtService;
import com.boot.jwt.core.key.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ResourceCondition;
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
                .signingKeyResolver(new JwtSigningKeyResolver(keystore))
                .build();
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
        @Conditional(JKSAvailableCondition.class)
        public Keystore jksKeystore(JwtAuthProperties jwtAuthProperties) throws IOException {

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


    @EnableWebSecurity
    public static class JwtSecurityConfigAdapterImpl extends JwtSecurityConfigAdapter {

        @Autowired
        @Override
        public void setJwtAuthProperties(JwtAuthProperties jwtAuthProperties) {
            super.setJwtAuthProperties(jwtAuthProperties);
        }

        @Autowired
        @Override
        public void setJwtService(JwtService jwtService) {
            super.setJwtService(jwtService);
        }
    }


    public static class JKSAvailableCondition extends ResourceCondition {

        protected JKSAvailableCondition() {
            super("JWtAuth", "jwt.auth", "keyStore", new String[]{});
        }
    }

}
