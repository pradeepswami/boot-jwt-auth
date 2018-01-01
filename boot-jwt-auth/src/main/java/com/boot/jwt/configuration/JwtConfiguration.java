package com.boot.jwt.configuration;

import com.boot.jwt.core.JJwtServiceImpl;
import com.boot.jwt.core.JwtService;
import com.boot.jwt.security.RestClientAuthInterceptor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfiguration {


    @Bean
    @ConditionalOnMissingBean(JwtService.class)
    public JwtService jwtService() {
        return JJwtServiceImpl.JwtServiceBuilder.getInstance().build();
    }

    @Bean
    public RestClientAuthInterceptor restClientAuthInterceptor() {
        return new RestClientAuthInterceptor();

    }

}
