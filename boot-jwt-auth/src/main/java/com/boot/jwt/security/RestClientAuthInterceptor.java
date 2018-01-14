package com.boot.jwt.security;

import com.boot.jwt.core.JwtService;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.support.HttpRequestWrapper;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

public class RestClientAuthInterceptor implements ClientHttpRequestInterceptor {

    public static final String BEARER = "Bearer ";
    private JwtService jjwtServiceImpl;

    private JwtAdditionalClaim jwtAdditionalClaim;

    public RestClientAuthInterceptor(JwtService jjwtServiceImpl) {
        this(jjwtServiceImpl, new EmptyAdditionalClaim());
    }

    public RestClientAuthInterceptor(JwtService jjwtServiceImpl, JwtAdditionalClaim jwtAdditionalClaim) {
        Assert.notNull(jjwtServiceImpl, "JwtService is null");
        Assert.notNull(jwtAdditionalClaim, "JwtAdditionalClaim is null");
        this.jjwtServiceImpl = jjwtServiceImpl;
        this.jwtAdditionalClaim = jwtAdditionalClaim;
    }

    public static final String AUTH_HEADER = "Authorization";

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {

        HttpRequest wrapper = new HttpRequestWrapper(request);
        wrapper.getHeaders().set(AUTH_HEADER, BEARER + jjwtServiceImpl.generateToken(jwtAdditionalClaim.claims()));

        return execution.execute(wrapper, body);
    }


    public static class EmptyAdditionalClaim implements JwtAdditionalClaim {
        @Override
        public Map<String, String> claims() {
            return Collections.emptyMap();
        }
    }

}
