package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.model.TokenResponse;
import jakarta.validation.constraints.NotBlank;
import org.springframework.validation.annotation.Validated;

@Validated
public interface TokenProviderService {

	@Validated
	TokenResponse token(@NotBlank String username, @NotBlank String password);

	@Validated
	TokenResponse refresh(@NotBlank String refreshToken);
}
