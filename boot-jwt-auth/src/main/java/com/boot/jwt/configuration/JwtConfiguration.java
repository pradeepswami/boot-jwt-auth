package com.boot.jwt.configuration;

import com.boot.jwt.core.JJwtServiceImpl;
import com.boot.jwt.core.JwtService;
import com.boot.jwt.core.key.JksKeystore;
import com.boot.jwt.core.key.JksPublicKeyRegistry;
import com.boot.jwt.core.key.JwtSigningKeyResolver;
import com.boot.jwt.security.RestClientAuthInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.IOException;

@Configuration
public class JwtConfiguration {

    @Autowired
    private JwtAuthProperties jwtAuthProperties;

    @Bean
    @ConditionalOnMissingBean(JwtService.class)
    public JwtService jwtService() throws IOException {

        Resource keyStoreResource = jwtAuthProperties.getKeyStore();

        JksKeystore jksKeystore = new JksKeystore(keyStoreResource.getInputStream(),
                jwtAuthProperties.getStorePasswordChar(),
                jwtAuthProperties.getKeyPasswordChar(),
                jwtAuthProperties.getAlias());

        JksPublicKeyRegistry registry = new JksPublicKeyRegistry(keyStoreResource.getInputStream(),
                jwtAuthProperties.getStorePasswordChar(),
                jwtAuthProperties.getTrustedAppKeys());
        jksKeystore.setPublicKeyRegistry(registry);

        return JJwtServiceImpl.JwtServiceBuilder.getInstance()
                .appName(jwtAuthProperties.getAppName())
                .instanceId(jwtAuthProperties.getInstanceId())
                .algo("rsa")
                .keystore(jksKeystore)
                .signingKeyResolver(new JwtSigningKeyResolver(jksKeystore))
                .build();
    }

    @Bean
    public RestClientAuthInterceptor restClientAuthInterceptor() {
        return new RestClientAuthInterceptor();

    }

}
