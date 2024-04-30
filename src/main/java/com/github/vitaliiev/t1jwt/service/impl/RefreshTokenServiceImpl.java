package com.github.vitaliiev.t1jwt.service.impl;

import com.github.vitaliiev.t1jwt.model.RefreshToken;
import com.github.vitaliiev.t1jwt.model.User;
import com.github.vitaliiev.t1jwt.repository.RefreshTokenRepository;
import com.github.vitaliiev.t1jwt.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

	private final RefreshTokenRepository repository;

	@Transactional
	@Override
	public RefreshToken createToken(User user, Instant createdAt) {
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
