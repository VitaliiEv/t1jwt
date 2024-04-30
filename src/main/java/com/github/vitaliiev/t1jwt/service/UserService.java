package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.model.Role;
import com.github.vitaliiev.t1jwt.model.User;
import jakarta.validation.constraints.Size;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Validated
public interface UserService extends UserDetailsService {
	User findByUsername(String username) throws UsernameNotFoundException;

	Page<User> getUsers(Pageable pageable);

	User createUser(String username, String password) throws UserExistsException;

	void changePassword(String oldPassword, String newPassword) throws UsernameNotFoundException;

	void delete(String username) throws UsernameNotFoundException;

	List<Role> userRole(String username);

	@Validated
	User assignRoles(String username, @Size(max = 10) List<String> names);

	@Validated
	User revokeRoles(String username, @Size(max = 10) List<String> names);
}
