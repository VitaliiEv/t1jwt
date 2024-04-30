package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.T1jwtException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.Set;

@ResponseStatus(HttpStatus.CONFLICT)
public class RoleExistsException extends T1jwtException {

	public RoleExistsException(String roleName) {
		super(String.format("Roles already exists: %s", roleName));
	}
}
