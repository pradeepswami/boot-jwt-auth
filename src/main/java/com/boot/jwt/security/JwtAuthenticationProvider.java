package com.boot.jwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

import com.boot.jwt.service.JwtService;

public class JwtAuthenticationProvider implements AuthenticationProvider {

	private final static Logger LOG = LoggerFactory.getLogger(JwtAuthenticationProvider.class);

	private JwtService jwtService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Assert.isInstanceOf(JwtAuthenticationToken.class, authentication);
		JwtAuthenticationToken authToken = (JwtAuthenticationToken) authentication;

		Jwt<Header, Claims> jwt = null;
		try {
			jwt = jwtService.paserJwt(authToken.getToken());
		} catch (Exception e) {
			LOG.error("JWT authentication failed.", e);
			throw new JwtAuthenticationException(e.getMessage(), e);
		}

		return createAuthentication(jwt, authToken.getToken());
	}

	JwtAuthenticationToken createAuthentication(Jwt<Header, Claims> token, String jwtStr) {
		JwtAuthenticationToken jwt = new JwtAuthenticationToken(token.getBody().getId(), jwtStr);
		return jwt;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return JwtAuthenticationToken.class.isAssignableFrom(authentication);

	}

	public void setJwtService(JwtService jwtService) {
		this.jwtService = jwtService;
	}

}
