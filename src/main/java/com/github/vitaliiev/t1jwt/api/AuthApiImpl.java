package com.github.vitaliiev.t1jwt.api;

import com.github.vitaliiev.t1jwt.model.RefreshTokenRequest;
import com.github.vitaliiev.t1jwt.model.TokenRequest;
import com.github.vitaliiev.t1jwt.model.TokenResponse;
import com.github.vitaliiev.t1jwt.service.TokenProviderService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthApiImpl implements AuthApiDelegate {

	private final TokenProviderService tokenProviderService;

	@Override
	public ResponseEntity<TokenResponse> token(TokenRequest tokenRequest) {
		TokenResponse token = tokenProviderService.token(tokenRequest.getUsername(), tokenRequest.getPassword());
		return ResponseEntity.ok(token);
	}

	@Override
	public ResponseEntity<TokenResponse> refresh(RefreshTokenRequest refreshTokenRequest) {
		TokenResponse refresh = tokenProviderService.refresh(refreshTokenRequest.getRefreshToken());
		return ResponseEntity.ok(refresh);
	}
}
