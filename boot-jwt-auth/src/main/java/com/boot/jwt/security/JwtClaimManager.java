package com.boot.jwt.security;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;

public interface JwtClaimManager {

    public Object getPrincipal(Jwt<Header, Claims> jwt);

}
