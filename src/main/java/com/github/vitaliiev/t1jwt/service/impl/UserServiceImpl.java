package com.github.vitaliiev.t1jwt.service.impl;

import com.github.vitaliiev.t1jwt.model.Role;
import com.github.vitaliiev.t1jwt.model.User;
import com.github.vitaliiev.t1jwt.repository.UserRepository;
import com.github.vitaliiev.t1jwt.security.DefaultRoles;
import com.github.vitaliiev.t1jwt.security.JpaUserDetailsImpl;
import com.github.vitaliiev.t1jwt.security.SecurityUtils;
import com.github.vitaliiev.t1jwt.service.*;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.parameters.P;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;
	private final RolesService rolesService;
	private final PasswordEncoder passwordEncoder;
	private final GrantedAuthoritiesMapper grantedAuthoritiesMapper;

	private static final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	@PostConstruct
	void init() {
		if (!userRepository.existsByUsername("admin")) {
			createUserInternal("admin", "admin", Set.of(DefaultRoles.ADMIN.name()));
		}
	}

//	@Override
//	@Transactional
//	public void createUser(UserDetails user) {
//		Assert.isTrue(!userRepository.existsByUsername(user.getUsername()), "user should not exist");
//		Assert.hasText(user.getUsername(), "Username may not be empty or null");
//		Assert.notNull(user.getAuthorities(), "Authorities list must not be null");
//		User createdUser = new User();
//		createdUser.setUsername(user.getUsername());
//		createdUser.setPassword(user.getPassword());
//		createdUser.setRoles(rolesService.getRoles(user.getAuthorities()));
//		userRepository.save(createdUser);
//	}

	@Override
	@Transactional
	public Page<User> getUsers(Pageable pageable) {
		return userRepository.findAll(pageable);
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
	public void changePassword(String oldPassword, String newPassword) throws UsernameNotFoundException {
		String currentUser = SecurityUtils.getAuthenticatedUsername();
		userRepository.findByUsername(currentUser)
				.map(u -> {
					if (passwordEncoder.matches(oldPassword, u.getPassword())) {
						u.setPassword(passwordEncoder.encode(newPassword));
						return userRepository.save(u);
					} else {
						throw new BadCredentialsException("Old password doesn't match");
					}
				})
				.orElseThrow(() -> new UsernameNotFoundException(currentUser));
	}

	@Override
	@Transactional
	public void delete(String username) throws UsernameNotFoundException {
		if (username.equals("admin")) {
			throw new AccessDeniedException(String.format("Cant delete default user: %s", username));
		}
		if (userRepository.deleteByUsername(username) != 1) {
			throw new UsernameNotFoundException(username);
		}
	}

	@Override
	@Transactional
	public List<Role> userRole( String username) {
		return userRepository.findByUsername(username)
				.map(User::getRoles)
				.orElseThrow(() ->  new UsernameNotFoundException(username));
	}

	@Override
	public User assignRoles(String username, List<String> names) {
		Optional<User> optionalUser = userRepository.findByUsername(username);
		if (optionalUser.isPresent()) {
			Set<String> normalized = names.stream()
					.map(rolesService::normalize)
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
			throw new UsernameNotFoundException(username);
		}
	}

	@Override
	@Transactional
	public User revokeRoles(String username, List<String> names) {
		Optional<User> optionalUser = userRepository.findByUsername(username);
		if (optionalUser.isPresent()) {
			Set<String> normalized = names.stream()
					.map(rolesService::normalize)
					.collect(Collectors.toSet());
			User user = optionalUser.get();
			List<Role> roles = user.getRoles();
			List<Role> remaining = roles.stream()
					.filter(role -> normalized.contains(role.getName()))
					.toList();
			if (roles.size() == remaining.size()) {
				return user;
			} else {
				user.setRoles(remaining);
				return userRepository.save(user);
			}
		} else {
			throw new UsernameNotFoundException(username);
		}
	}

	@Override
	@Transactional
	public User findByUsername(String username) throws UsernameNotFoundException {
		return userRepository.findByUsername(username)
				.orElseThrow(() -> new UsernameNotFoundException(username));
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


//	@Override
//	@Transactional
//	public UserDetails updatePassword(UserDetails user, String newPassword) {
//		Assert.isTrue(userRepository.existsByUsername(user.getUsername()), "user should exist");
//		return userRepository.findByUsername(user.getUsername())
//				.map(u -> {
//					u.setPassword(newPassword);
//					return userRepository.save(u);
//				})
//				.map(this::createUserDetails)
//				.orElseThrow(() -> new UsernameNotFoundException(user.getUsername()));
//	}

//	@Override
//	@Transactional
//	public void updateUser(UserDetails user) {
//		userRepository.findByUsername(user.getUsername())
//				.map(u -> {
//					List<Role> roles = rolesService.getRoles(user.getAuthorities());
//					u.setRoles(roles);
//					return userRepository.save(u);
//				})
//				.orElseThrow(() -> new UsernameNotFoundException(user.getUsername()));
//	}

//	@Override
//	@Transactional
//	public void deleteUser(String username) {
//		userRepository.deleteByUsername(username);
//	}

//	@Override
//	@Transactional
//	public void changePassword(String oldPassword, String newPassword) {
//		Authentication currentUser = securityContextHolderStrategy.getContext().getAuthentication();
//		if (currentUser == null) {
//			// This would indicate bad coding somewhere
//			throw new AccessDeniedException(
//					"Can't change password as no Authentication object found in context " + "for current user.");
//		}
//		String username = currentUser.getName();
//		userRepository.findByUsername(username)
//				.map(u -> {
//					u.setPassword(newPassword);
//					User saved = userRepository.save(u);
//					updateSecurityContext(currentUser, createUserDetails(saved));
//					return saved;
//				})
//				.orElseThrow(() -> new UsernameNotFoundException(username));
//	}

//
//	private void updateSecurityContext(Authentication currentAuthentication, UserDetails userDetails) {
//		SecurityContext context = securityContextHolderStrategy.createEmptyContext();
//		UsernamePasswordAuthenticationToken newAuthentication =
//				UsernamePasswordAuthenticationToken.authenticated(userDetails,
//						null, userDetails.getAuthorities());
//		newAuthentication.setDetails(currentAuthentication.getDetails());
//		context.setAuthentication(newAuthentication);
//	}
//	@Override
//	@Transactional
//	public boolean userExists(String username) {
//		return userRepository.existsByUsername(username);
//	}
}
