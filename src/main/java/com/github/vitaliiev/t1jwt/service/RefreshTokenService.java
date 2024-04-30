package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.model.RefreshToken;
import com.github.vitaliiev.t1jwt.model.User;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenService {

	RefreshToken createToken(User user, Instant createdAt);

	Optional<RefreshToken> findByUsername(String username);
}
