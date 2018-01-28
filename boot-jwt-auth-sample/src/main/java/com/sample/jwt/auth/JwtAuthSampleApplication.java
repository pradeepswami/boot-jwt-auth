package com.sample.jwt.auth;

import com.boot.jwt.security.JwtClaimManager;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.security.Principal;

@SpringBootApplication
public class JwtAuthSampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtAuthSampleApplication.class);
    }


    @Bean
    public JwtClaimManager jwtClaimManager() {
        return new JwtClaimManager() {
            @Override
            public Object getPrincipal(Jwt<Header, Claims> jwt) {
                final String id = jwt.getBody().getId();

                return new Principal() {
                    @Override
                    public String getName() {
                        return id;
                    }

                    @Override
                    public String toString() {
                        return "$classname{}" + id;
                    }
                };
            }
        };
    }


}
