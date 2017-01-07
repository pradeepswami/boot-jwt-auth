package com.boot.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

import org.apache.commons.lang3.time.DateUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.boot.jwt.configuration.JwtAuthProperties;

@Service
public class JwtService {

	@Autowired
	private JwtAuthProperties jwtAuthProperties;

	@Autowired
	private KeyStoreAdapter keyStoreAdapter;

	public String generateToken() {
		Date now = new Date();

		//@formatter:off
		return Jwts.builder()
		.setId(jwtAuthProperties.getAppName())
		.setIssuedAt(now)
		.setExpiration(DateUtils.addSeconds(now, jwtAuthProperties.getExpSeconds()))
		.setSubject(jwtAuthProperties.getAppName())
		.signWith(SignatureAlgorithm.RS256, keyStoreAdapter.getPrivateKey())
		.compact();
		//@formatter:on

	}

	public Jwt<Header, Claims> paserJwt(String jwt) {
		//@formatter:off
		Jwt<Header, Claims> token = Jwts.parser()
		.setSigningKeyResolver(keyStoreAdapter.getSigningKeyResolver())
		.parse(jwt);
		//@formatter:on

		return token;
	}
}
