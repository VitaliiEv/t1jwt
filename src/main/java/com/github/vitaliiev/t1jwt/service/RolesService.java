package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.model.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Set;

@Validated
public interface RolesService {

	@Validated
	Role createRole(@NotBlank String roleName) throws RoleExistsException;

	@Validated
	Role getRole(@NotBlank String roleName) throws RoleNotFoundException;

	Page<Role> getRoles(Pageable pageable);

	@Validated
	void deleteRole(@NotBlank String roleName) throws RoleNotFoundException;

	@Validated
	List<Role> getRoles(@Size(max = 10) Set<String> roleNames) throws RoleNotFoundException;

	@Validated
	Set<GrantedAuthority> toGrantedAuthorities(@Size(max = 10) List<Role> roles);
}
