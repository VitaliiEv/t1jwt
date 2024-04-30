package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.T1jwtException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.Set;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class RoleNotFoundException extends T1jwtException {

	public RoleNotFoundException(String roleName) {
		super(String.format("Roles not found: %s", roleName));
	}

	public RoleNotFoundException(Set<String> roles) {
		super(String.format("Roles not found: %s", String.join(", ", roles)));
	}
}
