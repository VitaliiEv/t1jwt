package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.model.RefreshToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;

public interface TokenValidatorService {

	Jws<Claims> verifyAccessToken(String accessToken) throws JwtException;

	Jws<Claims> verifyRefreshToken(String refreshToken, RefreshToken savedRefreshToken) throws JwtException;
}
