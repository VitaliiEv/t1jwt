package com.github.vitaliiev.t1jwt.security;

import com.github.vitaliiev.t1jwt.service.TokenValidatorService;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.util.StringUtils;

import java.util.Collection;

@Slf4j
public class JWTAuthenticationProvider implements AuthenticationProvider {

	private final TokenValidatorService tokenValidatorService;
	private GrantedAuthoritiesMapper grantedAuthoritiesMapper;

	public JWTAuthenticationProvider(TokenValidatorService tokenValidatorService) {
		this.tokenValidatorService = tokenValidatorService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}
		if (authentication instanceof JWTAuthentication jwtAuthentication) {
			return authenticate(jwtAuthentication);
		}
		return null;
	}

	private Authentication authenticate(JWTAuthentication jwtAuthentication) {
		if (jwtAuthentication.isAuthenticated()) {
			return jwtAuthentication;
		}
		String token = jwtAuthentication.getDetails();
		if (!StringUtils.hasText(token)) {
			return null;
		}

		Jws<Claims> credentials = null;
		try {
			credentials = tokenValidatorService.verifyAccessToken(token);
		} catch (ExpiredJwtException e) {
			throw new CredentialsExpiredException("Token expired", e);
		} catch (PrematureJwtException e) {
			throw new BadCredentialsException("Token issued at before current date", e);
		} catch (JwtException | IllegalArgumentException e) {
			throw new BadCredentialsException("Bad token", e);
		}
		Claims payload = credentials.getPayload();
		String username = payload.getSubject();
		try {
			String scope = credentials.getPayload().get(SecurityUtils.SCOPE_CLAIM, String.class);
			Collection<? extends GrantedAuthority> authorities = SecurityUtils.parseJwtScopes(scope,
					grantedAuthoritiesMapper);
			return JWTAuthentication.authenticated(username, credentials, authorities);
		} catch (RequiredTypeException e) {
			log.warn(e.getMessage());
			throw new BadCredentialsException("Can't retrieve granted authorities", e);
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return JWTAuthentication.class.isAssignableFrom(authentication);
	}

	public void setAuthoritiesMapper(GrantedAuthoritiesMapper grantedAuthoritiesMapper) {
		this.grantedAuthoritiesMapper = grantedAuthoritiesMapper;
	}
}
