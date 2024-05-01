package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.T1jwtException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.Set;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class UserNotFoundException extends T1jwtException {

	public UserNotFoundException(String roleName) {
		super(String.format("Users not found: %s", roleName));
	}

}
