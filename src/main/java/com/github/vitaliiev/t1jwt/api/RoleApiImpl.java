package com.github.vitaliiev.t1jwt.api;

import com.github.vitaliiev.t1jwt.model.Role;
import com.github.vitaliiev.t1jwt.model.RoleDto;
import com.github.vitaliiev.t1jwt.service.RolesService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RoleApiImpl implements RoleApiDelegate {

	private final RolesService rolesService;

	@Override
	public ResponseEntity<RoleDto> createRole(RoleDto roleDto) {
		Role role = rolesService.createRole(roleDto.getName());
		return ResponseEntity.ok(mapToDto(role));

	}

	@Override
	public ResponseEntity<Void> deleteRole(String rolename) {
		rolesService.deleteRole(rolename);
		return ResponseEntity.ok().build();
	}

	@Override
	public ResponseEntity<RoleDto> role(String rolename) {
		Role role = rolesService.getRole(rolename);
		return ResponseEntity.ok(mapToDto(role));
	}

	@Override
	public ResponseEntity<List<RoleDto>> roles(Pageable pageable) {
		List<RoleDto> roleDtos = rolesService.getRoles(pageable)
				.map(this::mapToDto)
				.toList();
		return ResponseEntity.ok(roleDtos);
	}

	private RoleDto mapToDto(Role role) {
		return new RoleDto()
				.name(role.getName());
	}
}
