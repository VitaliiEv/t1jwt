package com.github.vitaliiev.t1jwt.service.impl;

import com.github.vitaliiev.t1jwt.config.JwtProperties;
import com.github.vitaliiev.t1jwt.model.RefreshToken;
import com.github.vitaliiev.t1jwt.service.TokenValidatorService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.function.UnaryOperator;

import static com.github.vitaliiev.t1jwt.security.SecurityUtils.*;
import static com.github.vitaliiev.t1jwt.security.SecurityUtils.SCOPE_CLAIM;

@Service
public class TokenValidatorServiceImpl implements TokenValidatorService {

	private final SecretKey key;
	private final JwtParser jwtParser;

	public TokenValidatorServiceImpl(JwtProperties jwtProperties) {
		String secret = jwtProperties.getSecretKey();
		byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
		key = Keys.hmacShaKeyFor(keyBytes);
		jwtParser = Jwts.parser()
				.verifyWith(key)
				.build();
	}

	@Override
	public Jws<Claims> verifyAccessToken(String accessToken) throws JwtException {
		Jws<Claims> jws = jwtParser.parseSignedClaims(accessToken);
		String username = jws.getPayload().getSubject();
		Jws<Claims> claimsJws = verifyInternal(accessToken, builder -> builder.requireSubject(username));
		String string = claimsJws.getPayload().get(SCOPE_CLAIM, String.class);
		for (GrantedAuthority grantedAuthority : parseJwtScopes(string, null)) {
			String authority = grantedAuthority.getAuthority();
			if (removeRolePrefix(authority).equals(REFRESH_SCOPE)) {
				throw new BadCredentialsException("Refresh token passed instead of access token");
			}
		}
		return claimsJws;
	}

	@Override
	public Jws<Claims> verifyRefreshToken(String refreshToken, RefreshToken savedRefreshToken) throws JwtException {
		return verifyInternal(refreshToken, builder -> builder.requireId(savedRefreshToken.getId().toString())
				.requireSubject(savedRefreshToken.getUser().getUsername())
				.requireIssuedAt(Date.from(savedRefreshToken.getCreatedAt())));
	}

	private Jws<Claims> verifyInternal(String token, UnaryOperator<JwtParserBuilder> customizer) throws JwtException {
		Jws<Claims> jws = customizer.apply(Jwts.parser().verifyWith(key))
				.build()
				.parseSignedClaims(token);
		Claims payload = jws.getPayload();
		Instant now = Instant.now();
		Instant issuedAt = payload.getIssuedAt().toInstant();
		if (issuedAt.isAfter(now)) {
			throw new PrematureJwtException(jws.getHeader(),payload, "Error when verifying issuedAt claim of refresh token");
		}
		return jws;
	}
}
