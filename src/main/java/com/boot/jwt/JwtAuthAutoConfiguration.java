package com.boot.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.boot.jwt.security.JwtAuthenticationFilter;
import com.boot.jwt.security.JwtAuthenticationProvider;
import com.boot.jwt.security.TokenAuthenticationEntryPoint;
import com.boot.jwt.service.JwtAuthProperties;
import com.boot.jwt.service.JwtService;
import com.boot.jwt.service.KeyStoreAdapter;

@EnableWebSecurity
@EnableConfigurationProperties(JwtAuthProperties.class)
public class JwtAuthAutoConfiguration extends WebSecurityConfigurerAdapter {

	@Bean
	public KeyStoreAdapter keyStoreAdapter() {
		return new KeyStoreAdapter();
	}

	@Bean
	public JwtService jwtService() {
		return new JwtService();
	}

	@Bean
	public JwtAuthenticationFilter jwtAuthenticationFilter() {
		return new JwtAuthenticationFilter();
	}

	@Autowired
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		JwtAuthenticationProvider provider = new JwtAuthenticationProvider();
		provider.setJwtService(jwtService());
		auth.authenticationProvider(provider);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// formatter:off
		http.exceptionHandling().authenticationEntryPoint(new TokenAuthenticationEntryPoint());

		http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class).authorizeRequests()
				.antMatchers("/**");
		// formatter:on
	}
}
