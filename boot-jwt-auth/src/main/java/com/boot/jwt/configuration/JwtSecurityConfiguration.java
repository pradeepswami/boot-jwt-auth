package com.boot.jwt.configuration;

import com.boot.jwt.core.JJwtServiceImpl;
import com.boot.jwt.security.JwtAuthenticationFilter;
import com.boot.jwt.security.JwtAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
@Import(JwtConfiguration.class)
public class JwtSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private JJwtServiceImpl JJwtServiceImpl;

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider();
        provider.setJJwtServiceImpl(JJwtServiceImpl);
        auth.authenticationProvider(provider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // formatter:off
        http
                .httpBasic().disable()
                .csrf().disable()
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        // formatter:on
    }

}
