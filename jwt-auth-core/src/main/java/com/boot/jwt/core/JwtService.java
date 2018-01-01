package com.boot.jwt.core;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;

import java.util.Map;

public interface JwtService {

    String generateToken(Map<String, String> additionalClaims);

    Jwt<Header, Claims> paserJwt(String jwt);
}
