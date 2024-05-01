package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.model.RefreshToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.validation.annotation.Validated;

@Validated
public interface TokenValidatorService {

	@Validated
	Jws<Claims> verifyAccessToken(@NotBlank String accessToken) throws JwtException;

	@Validated
	Jws<Claims> verifyRefreshToken(@NotBlank String refreshToken, @NotNull RefreshToken savedRefreshToken) throws JwtException;
}
