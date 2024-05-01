package com.github.vitaliiev.t1jwt.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

@Slf4j
public class JWTAuthenticationConverter implements AuthenticationConverter {

	private static final String PREFIX = "Bearer ";

	@Override
	public JWTAuthentication convert(HttpServletRequest request) {
		String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (StringUtils.hasText(authorization)) {
			if (authorization.startsWith(PREFIX)) {
				String jws = authorization.substring(PREFIX.length());
				return JWTAuthentication.unauthenticated(jws);
			}
			throw new BadCredentialsException("Unexpected authentication header format");
		}
		log.warn("Expected authorization header for request: {}", request.getServletPath());
		throw new BadCredentialsException("Expected authorization header for request: " + request.getServletPath());
	}
}
