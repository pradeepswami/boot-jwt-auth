package com.boot.jwt.configuration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@ConditionalOnProperty(prefix = "jwt.auth", name = "enabled", matchIfMissing = true)
@Import({JwtAuthProperties.class, JwtAuthConfiguration.class})
public class JwtAuthAutoConfiguration {


}
