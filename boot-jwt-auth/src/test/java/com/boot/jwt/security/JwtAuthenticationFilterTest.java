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
