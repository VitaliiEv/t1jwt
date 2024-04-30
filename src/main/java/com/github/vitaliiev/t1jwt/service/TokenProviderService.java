package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.model.TokenResponse;

public interface TokenProviderService {

	TokenResponse token(String username, String password);

	TokenResponse refresh(String refreshToken);
}
