package com.github.vitaliiev.t1jwt.service.impl;

import com.github.vitaliiev.t1jwt.model.RefreshToken;
import com.github.vitaliiev.t1jwt.model.User;
import com.github.vitaliiev.t1jwt.repository.RefreshTokenRepository;
import com.github.vitaliiev.t1jwt.service.RefreshTokenService;
import com.github.vitaliiev.t1jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

	private final RefreshTokenRepository repository;
	private final UserService userService;

	@Override
	@Transactional
	public RefreshToken createToken(String username, Instant createdAt)  throws UsernameNotFoundException {
		User user = userService.findByUsername(username);
		repository.deleteByUser(user);
		RefreshToken refreshToken = new RefreshToken();
		refreshToken.setUser(user);
		refreshToken.setCreatedAt(createdAt);
		return repository.save(refreshToken);
	}

	@Transactional
	@Override
	public Optional<RefreshToken> findByUsername(String username) {
		return repository.findByUsername(username);
	}
}
