package com.github.vitaliiev.t1jwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JWTAuthentication extends AbstractAuthenticationToken {

	private final String principal;
	private final transient Jws<Claims> credentials;

	private JWTAuthentication(String token) {
		super(null);
		super.setDetails(token);
		this.principal = null;
		this.credentials = null;
		setAuthenticated(false);
	}

	private JWTAuthentication(String principal, Jws<Claims> credentials,
	                          Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		setAuthenticated(true);
	}

	public static JWTAuthentication unauthenticated(String token) {
		return new JWTAuthentication(token);
	}

	public static JWTAuthentication authenticated(String principal, Jws<Claims> credentials,
	                                              Collection<? extends GrantedAuthority> authorities) {
		return new JWTAuthentication(principal, credentials, authorities);
	}

	@Override
	public Jws<Claims> getCredentials() {
		return credentials;
	}

	@Override
	public String getPrincipal() {
		return principal;
	}

	@Override
	public String getDetails() {
		return (String) super.getDetails();
	}
}
