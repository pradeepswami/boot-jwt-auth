package com.boot.jwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;

public class DefaultJwtClaimManager implements JwtClaimManager {
    @Override
    public Object getPrincipal(Jwt<Header, Claims> jwt) {
        return jwt.getBody().getId();
    }
}
