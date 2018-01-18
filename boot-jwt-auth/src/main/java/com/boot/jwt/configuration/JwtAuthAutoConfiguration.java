package com.boot.jwt.configuration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@ConditionalOnProperty(prefix = "jwt.auth", name = "enabled")
@EnableConfigurationProperties({JwtAuthProperties.class})
@Import({JwtAuthConfiguration.class})
public class JwtAuthAutoConfiguration {


}
