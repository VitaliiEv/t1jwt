package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.T1jwtException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class UserExistsException extends T1jwtException {

	public UserExistsException(String userName) {
		super(String.format("User already exists: %s", userName));
	}
}
