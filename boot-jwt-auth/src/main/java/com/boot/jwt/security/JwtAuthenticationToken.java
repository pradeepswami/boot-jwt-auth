package com.boot.jwt.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = 1L;
	private String jwt;
	private String principal;

	public JwtAuthenticationToken(String jwt) {
		super(null);
		this.jwt = jwt;
	}

	public JwtAuthenticationToken(String principal, String jwt) {
		super(null);
		this.principal = principal;
		this.jwt = jwt;
		super.setAuthenticated(true);
	}

	public String getToken() {
		return jwt;
	}

	@Override
	public Object getCredentials() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Object getPrincipal() {
		return principal;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) {
		if (isAuthenticated) {
			throw new IllegalArgumentException(
					"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		}
		super.setAuthenticated(false);
	}

}
