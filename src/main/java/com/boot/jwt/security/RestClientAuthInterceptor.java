package com.boot.jwt.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.support.HttpRequestWrapper;
import org.springframework.stereotype.Component;

import com.boot.jwt.service.JwtService;

@Component
public class RestClientAuthInterceptor implements ClientHttpRequestInterceptor {

	@Autowired
	private JwtService jwtService;

	public static final String AUTH_HEADER = "Authorization";

	@Override
	public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
			throws IOException {

		HttpRequest wrapper = new HttpRequestWrapper(request);
		wrapper.getHeaders().set(AUTH_HEADER, "Bearer " + jwtService.generateToken());

		return execution.execute(wrapper, body);
	}

}
