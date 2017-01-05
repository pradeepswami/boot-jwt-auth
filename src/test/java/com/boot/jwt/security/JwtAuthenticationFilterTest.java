package com.boot.jwt.security;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.util.matcher.RequestMatcher;

@RunWith(MockitoJUnitRunner.class)
public class JwtAuthenticationFilterTest {
	@Mock
	private AuthenticationManager authenticationManager;
	@InjectMocks
	private JwtAuthenticationFilter testObject;

	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void testGenerateMatcher() throws Exception {

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/info");

		RequestMatcher requestMatcher = testObject.generateExcludeMatcher(Arrays.asList("/info", "/app/**"));

		System.err.println(requestMatcher.matches(request));

	}

}
