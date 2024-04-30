package com.github.vitaliiev.t1jwt.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

import java.util.Optional;

public class SecurityUtils {

	private static final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private SecurityUtils() {
		throw new IllegalStateException("Utility class exception");
	}

	public static String getAuthenticatedUsername() {
		return Optional.ofNullable(getAuthentication())
				.map(JWTAuthentication::getPrincipal)
				.orElse("");
	}

	private static JWTAuthentication getAuthentication() {
		Authentication authentication = securityContextHolderStrategy.getContext().getAuthentication();
		if (authentication instanceof JWTAuthentication jwtAuthentication) {
			return jwtAuthentication;
		}
		return null;
	}
}
