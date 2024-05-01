package com.github.vitaliiev.t1jwt.security;

import com.github.vitaliiev.t1jwt.T1jwtException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SecurityUtils {

	private static final String ROLE_PREFIX = "ROLE_";
	private static final String SCOPE_SEPARATOR = " ";
	public static final String SCOPE_CLAIM = "scope";
	public static final String REFRESH_SCOPE = "REFRESH";

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

	public static String getJwtScopes(Collection<? extends GrantedAuthority> authorities,
	                            GrantedAuthoritiesMapper grantedAuthoritiesMapper) {
		Collection<? extends GrantedAuthority> mapped = grantedAuthoritiesMapper == null ? authorities :
				grantedAuthoritiesMapper.mapAuthorities(authorities);
		return mapped
				.stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(SCOPE_SEPARATOR));
	}

	public static Collection<? extends GrantedAuthority> parseJwtScopes(String scope, GrantedAuthoritiesMapper grantedAuthoritiesMapper) {
		if (!StringUtils.hasText(scope)) {
			return Collections.emptyList();
		}
		List<? extends GrantedAuthority> authorities = Stream.of(scope.split(SCOPE_SEPARATOR))
				.map(SimpleGrantedAuthority::new)
				.toList();
		if (grantedAuthoritiesMapper == null) {
			return authorities;
		} else {
			return grantedAuthoritiesMapper.mapAuthorities(authorities);
		}
	}

	public static String removeRolePrefix(String roleName) {
		if (roleName.equals(ROLE_PREFIX)) {
			throw new T1jwtException("Illegal role name: " + roleName);
		} else if (roleName.startsWith(ROLE_PREFIX)) {
			return roleName.substring(ROLE_PREFIX.length()).toUpperCase();
		} else {
			return roleName.toUpperCase();
		}
	}
}
