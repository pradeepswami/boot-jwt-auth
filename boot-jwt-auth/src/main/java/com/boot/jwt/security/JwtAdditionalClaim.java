package com.boot.jwt.security;

import java.util.Map;

public interface JwtAdditionalClaim {

    Map<String, String> claims();

}
