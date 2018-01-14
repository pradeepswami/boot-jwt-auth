package com.boot.jwt.configuration;

import com.boot.jwt.core.JwtService;
import com.boot.jwt.security.JwtAuthenticationFilter;
import com.boot.jwt.security.JwtAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//@EnableWebSecurity
@Configuration
@ConditionalOnProperty(value = "jwt.auth.enabled", havingValue = "true", matchIfMissing = true)
public class JwtSecurityConfigAdapter extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private JwtAuthProperties jwtAuthProperties;

    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        JwtAuthenticationFilter authenticationFilter = new JwtAuthenticationFilter(jwtAuthProperties);
        authenticationFilter.setAuthenticationManager(this.authenticationManagerBean());
        return authenticationFilter;
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(jwtService);
        auth.authenticationProvider(provider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // formatter:off
        http
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .httpBasic().disable()
                .csrf().disable()
                .authorizeRequests().antMatchers("/unsecure/**").permitAll()
                .anyRequest().authenticated();
        // formatter:on
    }

}
