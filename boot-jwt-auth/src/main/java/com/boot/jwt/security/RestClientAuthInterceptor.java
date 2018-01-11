package com.boot.jwt.security;

import com.boot.jwt.core.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.support.HttpRequestWrapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collections;

@Component
public class RestClientAuthInterceptor implements ClientHttpRequestInterceptor {

    @Autowired
    private JwtService JJwtServiceImpl;

    public static final String AUTH_HEADER = "Authorization";

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {

        HttpRequest wrapper = new HttpRequestWrapper(request);
        wrapper.getHeaders().set(AUTH_HEADER, "Bearer " + JJwtServiceImpl.generateToken(Collections.emptyMap()));

        return execution.execute(wrapper, body);
    }

}
