package com.boot.jwt.security;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String BEARER = "Bearer ";

    public static final String AUTHORIZATION = "Authorization";

    private final static Logger LOG = LoggerFactory.getLogger(JwtAuthenticationFilter.class);


    public JwtAuthenticationFilter() {
        super("/**");
        setAuthenticationSuccessHandler(new NoOpAuthSuccessHandler());
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        String authHeader = request.getHeader(AUTHORIZATION);
        String jwt = StringUtils.substringAfter(authHeader, BEARER);

        JwtAuthenticationToken authRequest = new JwtAuthenticationToken(jwt);
        return getAuthenticationManager().authenticate(authRequest);
    }


    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String authHeader = request.getHeader(AUTHORIZATION);
        boolean rst = authHeader != null && authHeader.startsWith(BEARER);
        if (!rst) {
            LOG.debug("Skipping JwtAuthentication for url {}", request.getRequestURI());
        }
        return rst;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // call super to update auth in context
        super.successfulAuthentication(request, response, chain, authResult);
        chain.doFilter(request, response);
    }

}
