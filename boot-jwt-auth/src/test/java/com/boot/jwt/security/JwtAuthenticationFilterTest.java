package com.boot.jwt.security;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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

		RequestMatcher requestMatcher = testObject.generateExcludeMatcher(Arrays.asList("/info", "/**/app/**"));
		request.setServletPath("/info");
		assertTrue(requestMatcher.matches(request));
		request.setServletPath("/app");
		assertTrue(requestMatcher.matches(request));
		request.setServletPath("/test");
		assertFalse(requestMatcher.matches(request));

	}

}
