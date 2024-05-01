package com.github.vitaliiev.t1jwt.service.impl;

import com.github.vitaliiev.t1jwt.model.Role;
import com.github.vitaliiev.t1jwt.model.User;
import com.github.vitaliiev.t1jwt.repository.UserRepository;
import com.github.vitaliiev.t1jwt.security.DefaultRoles;
import com.github.vitaliiev.t1jwt.security.JpaUserDetailsImpl;
import com.github.vitaliiev.t1jwt.security.SecurityUtils;
import com.github.vitaliiev.t1jwt.service.RolesService;
import com.github.vitaliiev.t1jwt.service.UserExistsException;
import com.github.vitaliiev.t1jwt.service.UserNotFoundException;
import com.github.vitaliiev.t1jwt.service.UserService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;
	private final RolesService rolesService;
	private final PasswordEncoder passwordEncoder;

	@PostConstruct
	void init() {
		if (!userRepository.existsByUsername("admin")) {
			User admin = createUserInternal("admin", "admin", Set.of(DefaultRoles.ADMIN.name()));
			userRepository.save(admin);
		}
	}

	@Override
	@Transactional
	public Page<User> getUsers(Pageable pageable) {
		return userRepository.findAll(pageable == null ? Pageable.unpaged() : pageable);
	}

	@Override
	@Transactional
	public User createUser(String username, String password) throws UserExistsException {
		if (userRepository.existsByUsername(username)) {
			throw new UserExistsException(username);
		} else {
			User user = createUserInternal(username, password, Set.of(DefaultRoles.USER.name()));
			return userRepository.save(user);
		}
	}

	private User createUserInternal(String username, String password, Set<String> roleNames) {
		User createdUser = new User();
		createdUser.setUsername(username);
		createdUser.setPassword(passwordEncoder.encode(password));
		createdUser.setRoles(rolesService.getRoles(roleNames));
		return createdUser;
	}

	@Override
	@Transactional
	public void changePassword(String oldPassword, String newPassword) throws UserNotFoundException {
		String currentUser = SecurityUtils.getAuthenticatedUsername();
		userRepository.findByUsername(currentUser)
				.map(u -> {
					if (passwordEncoder.matches(oldPassword, u.getPassword())) {
						u.setPassword(passwordEncoder.encode(newPassword));
						return userRepository.save(u);
					} else {
						throw new BadCredentialsException("Provided old password doesn't match current password");
					}
				})
				.orElseThrow(() -> new UserNotFoundException(currentUser));
	}

	@Override
	@Transactional
	public void delete(String username) throws UserNotFoundException {
		if (username.equals("admin")) {
			throw new AccessDeniedException(String.format("Cant delete default user: %s", username));
		}
		if (userRepository.deleteByUsername(username) != 1) {
			throw new UserNotFoundException(username);
		}
	}

	@Override
	@Transactional
	public List<Role> userRole(String username) throws UserNotFoundException {
		return userRepository.findByUsername(username)
				.map(User::getRoles)
				.orElseThrow(() -> new UserNotFoundException(username));
	}

	@Override
	public User assignRoles(String username, List<String> names) throws UserNotFoundException {
		Optional<User> optionalUser = userRepository.findByUsername(username);
		if (optionalUser.isPresent()) {
			Set<String> normalized = names.stream()
					.map(SecurityUtils::removeRolePrefix)
					.collect(Collectors.toCollection(HashSet::new));
			User user = optionalUser.get();
			List<Role> roles = user.getRoles();
			roles.forEach(r -> normalized.remove(r.getName()));
			if (normalized.isEmpty()) {
				return user;
			} else {
				List<Role> newRoles = rolesService.getRoles(normalized);
				user.getRoles().addAll(newRoles);
				return userRepository.save(user);
			}
		} else {
			throw new UserNotFoundException(username);
		}
	}

	@Override
	@Transactional
	public User revokeRoles(String username, List<String> names) throws UserNotFoundException {
		Optional<User> optionalUser = userRepository.findByUsername(username);
		if (optionalUser.isPresent()) {
			Set<String> normalized = names.stream()
					.map(SecurityUtils::removeRolePrefix)
					.collect(Collectors.toSet());
			User user = optionalUser.get();
			List<Role> roles = user.getRoles();
			List<Role> remaining = roles.stream()
					.filter(role -> !normalized.contains(role.getName()))
					.collect(Collectors.toCollection(ArrayList::new));
			if (roles.size() == remaining.size()) {
				return user;
			} else {
				user.setRoles(remaining);
				return userRepository.save(user);
			}
		} else {
			throw new UserNotFoundException(username);
		}
	}

	@Override
	@Transactional
	public User findByUsername(String username) throws UserNotFoundException {
		return userRepository.findByUsername(username)
				.orElseThrow(() -> new UserNotFoundException(username));
	}

	@Override
	@Transactional
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return userRepository.findByUsername(username)
				.map(this::createUserDetails)
				.orElseThrow(() -> new UsernameNotFoundException(username));
	}

	private JpaUserDetailsImpl createUserDetails(User user) {
		Set<GrantedAuthority> grantedAuthorities = rolesService.toGrantedAuthorities(user.getRoles());
		return new JpaUserDetailsImpl(user.getUsername(), user.getPassword(), grantedAuthorities);
	}
}
