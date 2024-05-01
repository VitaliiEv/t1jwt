package com.github.vitaliiev.t1jwt.service;

import com.github.vitaliiev.t1jwt.model.Role;
import com.github.vitaliiev.t1jwt.model.User;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Validated
public interface UserService extends UserDetailsService {

	@Validated
	User findByUsername(@NotBlank String username) throws UserNotFoundException;

	Page<User> getUsers(Pageable pageable);

	@Validated
	User createUser(@NotBlank String username, @NotBlank String password) throws UserExistsException;

	@Validated
	void changePassword(@NotBlank String oldPassword, @NotBlank String newPassword) throws UserNotFoundException;

	@Validated
	void delete(@NotBlank String username) throws UserNotFoundException;

	@Validated
	List<Role> userRole(@NotBlank String username) throws UserNotFoundException;

	@Validated
	User assignRoles(String username, @Size(max = 10) List<String> names) throws UserNotFoundException;

	@Validated
	User revokeRoles(String username, @Size(max = 10) List<String> names) throws UserNotFoundException;
}
