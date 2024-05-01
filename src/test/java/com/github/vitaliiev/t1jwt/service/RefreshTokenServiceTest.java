package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.config.IntegrationTest;
import com.github.vitaliiev.t1jwt.model.RefreshToken;
import com.github.vitaliiev.t1jwt.model.User;
import com.github.vitaliiev.t1jwt.repository.RefreshTokenRepository;
import com.github.vitaliiev.t1jwt.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@IntegrationTest
class RefreshTokenServiceTest {

	@Autowired
	private RefreshTokenService refreshTokenService;
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Test
	void createToken_WhenUserExists_ExpectCreated() {
		String username = "user1";
		User user = createUser(username, "password");
		userRepository.save(user);
		RefreshToken token = refreshTokenService.createToken(username, new Date().toInstant());
		assertNotNull(token);
	}

	@Test
	void createToken_WhenUserDoesntExist_ExpectException() {
		String username = "user2";
		User user = createUser(username, "password");
		Instant createdAt = new Date().toInstant();
		assertThrows(UserNotFoundException.class, () -> refreshTokenService.createToken(username, createdAt));
	}

	@Test
	void createToken_WhenTokenExist_ExpectReplaced() {
		String username = "user3";
		User user = createUser(username, "password");
		userRepository.save(user);
		RefreshToken oldToken = refreshTokenService.createToken(username, new Date().toInstant());
		RefreshToken newToken = refreshTokenService.createToken(username, new Date().toInstant());
		assertEquals(newToken.getUser().getId(), oldToken.getUser().getId());
		assertNotEquals(newToken.getId(), oldToken.getId());
	}

	@Test
	void findByUsername_WhenExist_ExpectPresent() {
		String username = "user4";
		User user = createUser(username, "password");
		userRepository.save(user);
		RefreshToken refreshToken = createRefreshToken(user, Instant.now());
		refreshTokenRepository.save(refreshToken);
		Optional<RefreshToken> byUsername = refreshTokenService.findByUsername(username);
		assertTrue(byUsername.isPresent());
	}

	@Test
	void findByUsername_WhenNotExists_ExpectNotPresent() {
		String username = "user5";
		User user = createUser(username, "password");
		userRepository.save(user);
		Optional<RefreshToken> byUsername = refreshTokenService.findByUsername(username);
		assertTrue(byUsername.isEmpty());
	}

	@Test
	void findByUsername_WhenUserNotExists_ExpectNotPresent() {
		String username = "user6";
		Optional<RefreshToken> byUsername = refreshTokenService.findByUsername(username);
		assertTrue(byUsername.isEmpty());
	}

	public User createUser(String username, String password) {
		User user = new User();
		user.setUsername(username);
		user.setPassword(password);
		return user;
	}

	public RefreshToken createRefreshToken(User user, Instant createdAt) {
		RefreshToken refreshToken = new RefreshToken();
		refreshToken.setUser(user);
		refreshToken.setCreatedAt(createdAt);
		return refreshToken;
	}
}