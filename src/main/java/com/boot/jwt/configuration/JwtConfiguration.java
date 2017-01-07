package com.boot.jwt.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.boot.jwt.security.RestClientAuthInterceptor;
import com.boot.jwt.service.JwtService;
import com.boot.jwt.service.KeyStoreAdapter;

@Configuration
public class JwtConfiguration {

	@Bean
	public KeyStoreAdapter keyStoreAdapter() {
		return new KeyStoreAdapter();
	}

	@Bean
	public JwtService jwtService() {
		return new JwtService();
	}

	@Bean
	public RestClientAuthInterceptor restClientAuthInterceptor() {
		return new RestClientAuthInterceptor();

	}

}
