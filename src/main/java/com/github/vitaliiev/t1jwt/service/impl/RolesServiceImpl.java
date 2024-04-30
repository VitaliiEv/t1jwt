package com.github.vitaliiev.t1jwt.service.impl;

import com.github.vitaliiev.t1jwt.T1jwtException;
import com.github.vitaliiev.t1jwt.model.Role;
import com.github.vitaliiev.t1jwt.repository.RoleRepository;
import com.github.vitaliiev.t1jwt.security.DefaultRoles;
import com.github.vitaliiev.t1jwt.service.RoleExistsException;
import com.github.vitaliiev.t1jwt.service.RoleNotFoundException;
import com.github.vitaliiev.t1jwt.service.RolesService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RolesServiceImpl implements RolesService {

	private final RoleRepository roleRepository;
	private final GrantedAuthoritiesMapper grantedAuthoritiesMapper;
	private static final String ROLE_PREFIX = "ROLE_";

	@PostConstruct
	public void init() {
		for (DefaultRoles defaultRole : DefaultRoles.values()) {
			Role role = createRoleInternal(defaultRole.name());
			if (!roleRepository.exists(Example.of(role))) {
				roleRepository.save(role);
			}
		}
	}

	@Override
	@Transactional
	public Role createRole(String roleName) throws RoleExistsException {
		String trimmedRoleName = normalize(roleName);
		Role role = createRoleInternal(trimmedRoleName);
		if (roleRepository.exists(Example.of(role))) {
			throw new RoleExistsException(trimmedRoleName);
		} else {
			return roleRepository.save(role);
		}
	}

	@Override
	@Transactional
	public Role getRole(String roleName) throws RoleNotFoundException {
		return roleRepository.findByName(roleName)
				.orElseThrow(() -> new RoleNotFoundException(roleName));
	}

	@Override
	@Transactional
	public void deleteRole(String roleName) throws RoleNotFoundException {
		if (roleName.equals(DefaultRoles.ADMIN.name()) || roleName.equals(DefaultRoles.USER.name())) {
			throw new AccessDeniedException(String.format("Cant delete default role: %s", roleName));
		}
		if (roleRepository.deleteByName(roleName) != 1) {
			throw new RoleNotFoundException(roleName);
		}
	}

	@Override
	@Transactional
	public Page<Role> getRoles(Pageable pageable) {
		return roleRepository.findAll(pageable);
	}
//
//	private List<Role> createRolesInternal(Set<String> roleNames) {
//		Set<String> trimmedRoleNames = roleNames.stream()
//				.map(this::removePrefix)
//				.collect(Collectors.toSet());
//		List<Role> found = roleRepository.findByNames(trimmedRoleNames);
//		if (trimmedRoleNames.size() != found.size()) {
//			Set<String> notFound = new HashSet<>(trimmedRoleNames);
//			found.forEach(r -> notFound.remove(r.getName()));
//			List<Role> created = notFound.stream()
//					.map(this::createRoleInternal)
//					.toList();
//			List<Role> saved = roleRepository.saveAll(created);
//			return Stream.concat(found.stream(), saved.stream())
//					.toList();
//		}
//		return Collections.unmodifiableList(found);
//	}

	@Override
	@Transactional
	public List<Role> getRoles(Set<String> roleNames) throws RoleNotFoundException {
		Set<String> trimmedRoleNames = roleNames.stream()
				.map(this::normalize)
				.collect(Collectors.toSet());
		List<Role> found = roleRepository.findByNames(trimmedRoleNames);
		if (trimmedRoleNames.size() != found.size()) {
			Set<String> notFound = new HashSet<>(trimmedRoleNames);
			found.forEach(r -> notFound.remove(r.getName()));
			throw new RoleNotFoundException(notFound);
		}
		return found;
	}

	@Override
	@Transactional
	public List<Role> getRoles(Collection<? extends GrantedAuthority> authorities) throws RoleNotFoundException {
		Set<String> trimmedRoleNames = authorities.stream()
				.map(GrantedAuthority::getAuthority)
				.map(this::normalize)
				.collect(Collectors.toSet());
		List<Role> found = roleRepository.findByNames(trimmedRoleNames);
		if (trimmedRoleNames.size() != found.size()) {
			Set<String> notFound = new HashSet<>(trimmedRoleNames);
			found.forEach(r -> notFound.remove(r.getName()));
			throw new RoleNotFoundException(notFound);
		}
		return found;
	}

	@Override
	@Transactional
	public Set<GrantedAuthority> toGrantedAuthorities(List<Role> roles) {
		Set<GrantedAuthority> authorities = roles.stream()
				.map(Role::getName)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
		return Set.copyOf(grantedAuthoritiesMapper.mapAuthorities(authorities));
	}

	@Override
	public String normalize(String roleName) {
		if (roleName.equals(ROLE_PREFIX)) {
			throw new T1jwtException("Illegal role name: " + roleName);
		} else if (roleName.startsWith(ROLE_PREFIX)) {
			return roleName.substring(ROLE_PREFIX.length()).toUpperCase();
		} else {
			return roleName.toUpperCase();
		}
	}

	private Role createRoleInternal(String name) {
		Role role = new Role();
		role.setName(name);
		return role;
	}
}
