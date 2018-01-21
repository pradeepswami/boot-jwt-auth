package com.boot.jwt.configuration;

import com.boot.jwt.core.JwtService;
import com.boot.jwt.security.JwtAuthenticationFilter;
import com.boot.jwt.security.JwtAuthenticationProvider;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public abstract class JwtSecurityConfigAdapter extends WebSecurityConfigurerAdapter {

    private final static Logger LOG = LoggerFactory.getLogger(JwtSecurityConfigAdapter.class);

    private JwtAuthProperties jwtAuthProperties;
    private JwtService jwtService;


    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        JwtAuthenticationFilter authenticationFilter = new JwtAuthenticationFilter(jwtAuthProperties);
        authenticationFilter.setAuthenticationManager(this.authenticationManagerBean());
        return authenticationFilter;
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(jwtService);
        auth.authenticationProvider(provider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        JwtAuthProperties jwtAuthProperties = this.getApplicationContext().getBean(JwtAuthProperties.class);
        // formatter:off
        HttpSecurity httpSecurity = http
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .httpBasic().disable()
                .csrf().disable();
        String[] excludePath = jwtAuthProperties.getExcludePath();
        if (ArrayUtils.isNotEmpty(excludePath)) {
            LOG.info("Adding exclude path -> {}", StringUtils.join(excludePath, ","));
            httpSecurity.authorizeRequests()
                    .antMatchers(excludePath).permitAll();
        }
        httpSecurity.authorizeRequests().anyRequest().authenticated();
        // formatter:on
    }

    public void setJwtAuthProperties(JwtAuthProperties jwtAuthProperties) {
        this.jwtAuthProperties = jwtAuthProperties;
    }

    public void setJwtService(JwtService jwtService) {
        this.jwtService = jwtService;
    }
}
