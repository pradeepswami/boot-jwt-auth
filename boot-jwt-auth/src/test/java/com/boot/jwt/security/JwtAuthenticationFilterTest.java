package com.boot.jwt.security;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Arrays;

import static com.boot.jwt.security.JwtAuthenticationFilter.AUTHORIZATION;
import static com.boot.jwt.security.JwtAuthenticationFilter.BEARER;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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

    @Test
    public void requiresAuthentication_Typical() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader(AUTHORIZATION, BEARER + "token string");

        boolean rst = testObject.requiresAuthentication(request, response);

        assertTrue(rst);
    }

    @Test
    public void requiresAuthentication_when_noauth_header() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        boolean rst = testObject.requiresAuthentication(request, response);

        assertFalse(rst);
    }


    @Test
    public void requiresAuthentication_when_nobearer_header() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(AUTHORIZATION, "token string");
        MockHttpServletResponse response = new MockHttpServletResponse();

        boolean rst = testObject.requiresAuthentication(request, response);

        assertFalse(rst);
    }
}
