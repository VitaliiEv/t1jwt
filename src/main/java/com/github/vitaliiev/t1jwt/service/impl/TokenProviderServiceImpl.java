package com.github.vitaliiev.t1jwt.service.impl;

import com.github.vitaliiev.t1jwt.config.JwtProperties;
import com.github.vitaliiev.t1jwt.model.RefreshToken;
import com.github.vitaliiev.t1jwt.model.TokenResponse;
import com.github.vitaliiev.t1jwt.model.User;
import com.github.vitaliiev.t1jwt.service.RefreshTokenService;
import com.github.vitaliiev.t1jwt.service.TokenProviderService;
import com.github.vitaliiev.t1jwt.service.TokenValidatorService;
import com.github.vitaliiev.t1jwt.service.UserService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class TokenProviderServiceImpl implements TokenProviderService {

	private final JwtProperties jwtProperties;
	private final DaoAuthenticationProvider daoAuthenticationProvider;
	private final RefreshTokenService refreshTokenService;
	private final UserService userService;
	private final TokenValidatorService tokenValidatorService;

	private final SecretKey key;

	private static final String SCOPE_CLAIM = "scope";
	private final JwtParser jwtParser;

	public TokenProviderServiceImpl(JwtProperties jwtProperties, DaoAuthenticationProvider daoAuthenticationProvider,
	                                RefreshTokenService refreshTokenService, UserService userService, TokenValidatorService tokenValidatorService) {
		this.jwtProperties = jwtProperties;
		this.daoAuthenticationProvider = daoAuthenticationProvider;
		this.refreshTokenService = refreshTokenService;
		this.userService = userService;
		this.tokenValidatorService = tokenValidatorService;

		String secret = jwtProperties.getSecretKey();
		byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
		key = Keys.hmacShaKeyFor(keyBytes);
		jwtParser = Jwts.parser()
				.verifyWith(key)
				.build();
	}

	@Override
	public TokenResponse token(String username, String password) {
		Authentication unauthenticated = UsernamePasswordAuthenticationToken.unauthenticated(username, password);
		Authentication authenticated = daoAuthenticationProvider.authenticate(unauthenticated);
		Object principal = authenticated.getPrincipal();
		if (principal instanceof UserDetails userDetails) {
			Date issuedAt = new Date();
			String scopes = getScopes(authenticated.getAuthorities());
			return new TokenResponse()
					.accessToken(createAccessToken(userDetails, issuedAt, scopes))
					.refreshToken(createRefreshToken(userDetails, issuedAt));
		} else {
			throw new InternalAuthenticationServiceException("Wrong credentials type");
		}
	}

	private String createAccessToken(UserDetails userDetails, Date issuedAt, String scopes) {
		Instant expiresAt = issuedAt
				.toInstant()
				.plusSeconds(jwtProperties.getTokenValiditySeconds());
		return Jwts
				.builder()
				.id(UUID.randomUUID().toString())
				.issuedAt(issuedAt)
				.expiration(Date.from(expiresAt))
				.subject(userDetails.getUsername())
				.claim(SCOPE_CLAIM, scopes)
				.signWith(key)
				.compact();
	}

	private String createRefreshToken(UserDetails userDetails, Date issuedAt) {
		User user = userService.findByUsername(userDetails.getUsername());
		RefreshToken token = refreshTokenService.createToken(user, issuedAt.toInstant());
		Instant expiresAt = token.getCreatedAt()
				.plusSeconds(jwtProperties.getRefreshTokenValiditySeconds());
		return Jwts
				.builder()
				.id(token.getId().toString())
				.issuedAt(issuedAt)
				.expiration(Date.from(expiresAt))
				.subject(userDetails.getUsername())
				.signWith(key)
				.compact();
	}

	private String getScopes(Collection<? extends GrantedAuthority> authorities) {
		return authorities
				.stream().map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(" "));
	}

	@Override
	@Transactional
	public TokenResponse refresh(String refreshToken) {
		try {
			Jws<Claims> jws = jwtParser.parseSignedClaims(refreshToken);
			String username = jws.getPayload().getSubject();
			RefreshToken savedRefreshToken = refreshTokenService.findByUsername(username)
					.orElseThrow(() -> new BadCredentialsException("No refresh token found for user " + username));
			tokenValidatorService.verifyRefreshToken(refreshToken, savedRefreshToken);
			UserDetails userDetails = userService.loadUserByUsername(username);
			Date issuedAt = new Date();
			String scopes = getScopes(userDetails.getAuthorities());
			return new TokenResponse()
					.accessToken(createAccessToken(userDetails, issuedAt, scopes))
					.refreshToken(createRefreshToken(userDetails, issuedAt));
		} catch (JwtException | IllegalArgumentException e) {
			throw new BadCredentialsException("Error when parsing refresh token", e);
		}
	}
}
