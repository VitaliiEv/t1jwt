package com.github.vitaliiev.t1jwt.api;

import com.github.vitaliiev.t1jwt.model.*;
import com.github.vitaliiev.t1jwt.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserApiImpl implements UserApiDelegate {

	private final UserService userService;

	@Override
	public ResponseEntity<List<UserDto>> users(Pageable pageable) {
		List<UserDto> users = userService.getUsers(pageable)
				.map(this::mapToDto)
				.toList();
		return ResponseEntity.ok(users);
	}

	@Override
	@PreAuthorize("hasRole('ADMIN') or (#username == authentication.name)")
	public ResponseEntity<UserDto> user(@P("username") String username) {
		User user = userService.findByUsername(username);
		return ResponseEntity.ok(mapToDto(user));
	}

	@Override
	public ResponseEntity<UserDto> createUser(CreateUserRequest createUserRequest) {
		User user = userService.createUser(createUserRequest.getUsername(), createUserRequest.getPassword());
		return ResponseEntity.ok(mapToDto(user));
	}

	@Override
	public ResponseEntity<Void> password(ChangeUserPasswordRequest changeUserPasswordRequest) {
		userService.changePassword(changeUserPasswordRequest.getOldPassword(), changeUserPasswordRequest.getNewPassword());
		return ResponseEntity.ok().build();
	}

	@Override
	public ResponseEntity<Void> delete(String username) {
		userService.delete(username);
		return ResponseEntity.ok().build();
	}

	@Override
	@PreAuthorize("hasRole('ADMIN') or (#username == authentication.name)")
	public ResponseEntity<List<RoleDto>> userRole(@P("username") String username) {
		List<Role> roles = userService.userRole(username);
		return ResponseEntity.ok(mapToDto(roles));
	}

	@Override
	public ResponseEntity<UserDto> userAssignRole(String username, List<@Valid RoleDto> roleDto) {
		List<String> names = roleDto.stream().map(RoleDto::getName).toList();
		User user = userService.assignRoles(username, names);
		return ResponseEntity.ok(mapToDto(user));
	}

	@Override
	public ResponseEntity<UserDto> userRevokeRole(String username, List<@Valid RoleDto> roleDto) {
		List<String> names = roleDto.stream().map(RoleDto::getName).toList();
		User user = userService.revokeRoles(username, names);
		return ResponseEntity.ok(mapToDto(user));
	}

	private UserDto mapToDto(User user) {
		return new UserDto()
				.username(user.getUsername())
				.roles(mapToDto(user.getRoles()));
	}

	private List<RoleDto> mapToDto(List<Role> roles) {
		return roles.stream()
				.map(this::mapToDto)
				.toList();
	}

	private RoleDto mapToDto(Role role) {
		return new RoleDto()
				.name(role.getName());
	}
}
