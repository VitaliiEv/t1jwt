package com.github.vitaliiev.t1jwt.security;

import com.github.vitaliiev.t1jwt.config.IntegrationTest;
import com.github.vitaliiev.t1jwt.model.TokenResponse;
import com.github.vitaliiev.t1jwt.service.TokenProviderService;
import com.github.vitaliiev.t1jwt.service.TokenValidatorService;
import com.github.vitaliiev.t1jwt.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@IntegrationTest
class JWTAuthenticationProviderTest {

	@Autowired
	private UserService userService;
	@Autowired
	private TokenProviderService tokenProviderService;
	@Autowired
	private TokenValidatorService tokenValidatorService;

	private AuthenticationProvider provider;

	@BeforeEach
	void setUp() {
		provider = new JWTAuthenticationProvider(tokenValidatorService);
	}

	@Test
	void authenticate_WhenValidAccessToken_ExpectSuccess() {
		TokenResponse token = createUserAndToken("admin1", "admin1", List.of(DefaultRoles.ADMIN.name()));
		JWTAuthentication unauthenticated = JWTAuthentication.unauthenticated(token.getAccessToken());
		Authentication authenticate = provider.authenticate(unauthenticated);
		assertTrue(authenticate.isAuthenticated());
	}

	@Test
	void authenticate_WhenMalformedAccessToken_ExpectAuthenticationException() {
		JWTAuthentication unauthenticated = JWTAuthentication.unauthenticated("abcde");
		assertThrows(AuthenticationException.class, () -> provider.authenticate(unauthenticated));
	}

	@Test
	void authenticate_WhenRefreshTokenPassed_ExpectAuthenticationException() {
		TokenResponse token = createUserAndToken("admin2", "admin2", List.of(DefaultRoles.ADMIN.name()));
		JWTAuthentication unauthenticated = JWTAuthentication.unauthenticated(token.getRefreshToken());
		assertThrows(AuthenticationException.class, () -> provider.authenticate(unauthenticated));
	}

	private TokenResponse createUserAndToken(String username, String password, List<String> roles) {
		userService.createUser(username, password);
		userService.assignRoles(username, roles);
		return tokenProviderService.token(username, password);
	}
}