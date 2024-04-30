package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.model.Role;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Set;

public interface RolesService {

	Role createRole(String roleName) throws RoleExistsException;

	Role getRole(String roleName) throws RoleNotFoundException;

	Page<Role> getRoles(Pageable pageable);

	void deleteRole(String roleName) throws RoleNotFoundException;

	List<Role> getRoles(Set<String> roleNames) throws RoleNotFoundException;

	List<Role> getRoles(Collection<? extends GrantedAuthority> authorities) throws RoleNotFoundException;

	Set<GrantedAuthority> toGrantedAuthorities(List<Role> roles);

	String normalize(String roleName);
}
