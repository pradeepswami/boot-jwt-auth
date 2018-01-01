package com.boot.jwt.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import com.boot.jwt.configuration.JwtAuthProperties;

@Component
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public static final String BEARER = "Bearer ";

	public static final String AUTHORIZATION = "Authorization";

	private final static Logger LOG = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

	@Autowired
	private JwtAuthProperties jwtAuthProperties;

	private RequestMatcher excludePath;

	public JwtAuthenticationFilter() {
		super("/**");
		setAuthenticationSuccessHandler(new NoOpAuthSuccessHandler());
	}

	@PostConstruct
	public void init() {
		List<String> excludePaths = jwtAuthProperties.getExcludePaths();
		if (!CollectionUtils.isEmpty(excludePaths)) {
			LOG.debug("adding {} to exclude path", excludePaths);
			excludePath = this.generateExcludeMatcher(excludePaths);
		}
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		String authHeader = request.getHeader(AUTHORIZATION);
		String jwt = StringUtils.substringAfter(authHeader, BEARER);

		JwtAuthenticationToken authRequest = new JwtAuthenticationToken(jwt);
		return getAuthenticationManager().authenticate(authRequest);
	}

	@Autowired
	@Override
	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		super.setAuthenticationManager(authenticationManager);
	}

	protected RequestMatcher generateExcludeMatcher(List<String> excludePath) {
		List<RequestMatcher> nrm = new ArrayList<RequestMatcher>();
		for (String path : excludePath) {
			nrm.add(new AntPathRequestMatcher(path));
		}
		return new OrRequestMatcher(nrm);
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		if (excludePath != null && excludePath.matches(request)) {
			return false;
		}
		return super.requiresAuthentication(request, response);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain, Authentication authResult) throws IOException, ServletException {
		// call super to update auth in context
		super.successfulAuthentication(request, response, chain, authResult);
		chain.doFilter(request, response);
	}

}
