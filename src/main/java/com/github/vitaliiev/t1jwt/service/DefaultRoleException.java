package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.T1jwtException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class DefaultRoleException extends T1jwtException {

	public DefaultRoleException(String roleName) {
		super(String.format("Cant delete default role: %s", roleName));
	}
}
