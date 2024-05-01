package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.model.RefreshToken;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.PastOrPresent;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.annotation.Validated;

import java.time.Instant;
import java.util.Optional;

@Validated
public interface RefreshTokenService {

	@Validated
	RefreshToken createToken(@NotBlank String username, @PastOrPresent Instant createdAt) throws UsernameNotFoundException;

	@Validated
	Optional<RefreshToken> findByUsername(@NotBlank String username);
}
