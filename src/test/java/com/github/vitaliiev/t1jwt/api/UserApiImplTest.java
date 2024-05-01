package com.github.vitaliiev.t1jwt.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.vitaliiev.t1jwt.config.IntegrationTest;
import com.github.vitaliiev.t1jwt.model.*;
import com.github.vitaliiev.t1jwt.repository.RoleRepository;
import com.github.vitaliiev.t1jwt.repository.UserRepository;
import com.github.vitaliiev.t1jwt.security.DefaultRoles;
import com.github.vitaliiev.t1jwt.service.RolesService;
import com.github.vitaliiev.t1jwt.service.TokenProviderService;
import com.github.vitaliiev.t1jwt.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@AutoConfigureMockMvc
@IntegrationTest
class UserApiImplTest {
	@Autowired
	private MockMvc mockMvc;
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private UserService userService;
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private RolesService rolesService;
	@Autowired
	private RoleRepository roleRepository;
	@Autowired
	private TokenProviderService tokenProviderService;
	@Autowired
	private PasswordEncoder passwordEncoder;

	private static final String API_URL = "/api/v1/user";

	@Test
	void users_WhenAdminToken_ExpectDefaultAdmin() throws Exception {
		String token = adminAccessToken();
		mockMvc.perform(get(API_URL).header(AUTHORIZATION, token))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.[*]", hasSize(1)))
				.andExpect(jsonPath("$.[*].username", hasItem(equalTo("admin"))));
	}

	@Test
	void users_WhenUserToken_ExpectAccessDenied() throws Exception {
		String token = userAccessToken("user1", "user1");
		mockMvc.perform(get(API_URL).header(AUTHORIZATION, token))
				.andExpect(status().isForbidden());
	}

	@Test
	void users_WhenPagePresent_ExpectDefaultAdmin() throws Exception {
		String token = adminAccessToken();
		mockMvc.perform(get(API_URL)
						.param("page", "0")
						.header(AUTHORIZATION, token))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.[*]", hasSize(1)))
				.andExpect(jsonPath("$.[*].username", hasItem(equalTo("admin"))));
	}


	@Test
	void user_WhenAsAdminAndExists_ExpectNotFound() throws Exception {
		String username = "user2";
		userService.createUser(username, "user2");
		String token = adminAccessToken();
		mockMvc.perform(get(API_URL + "/{username}", username).header(AUTHORIZATION, token))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.username").value(username));
	}

	@Test
	void user_WhenAsAdminNotExists_ExpectReturned() throws Exception {
		String username = "user3";
		String token = adminAccessToken();
		mockMvc.perform(get(API_URL + "/{username}", username).header(AUTHORIZATION, token))
				.andExpect(status().isNotFound());

	}

	@Test
	void user_WhenAsUserAndMatch_ExpectReturned() throws Exception {
		String username = "user4";
		String token = userAccessToken(username, "user4");
		mockMvc.perform(get(API_URL + "/{username}", username).header(AUTHORIZATION, token))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.username").value(username));
	}

	@Test
	void user_WhenAsUserAndDontMatch_ExpectAccessDenied() throws Exception {
		String username = "user5";
		userService.createUser(username, "user5");
		String token = userAccessToken("some_user", "some_user");
		mockMvc.perform(get(API_URL + "/{username}", username).header(AUTHORIZATION, token))
				.andExpect(status().isForbidden());

	}

	@Test
	void createUser_WhenDontExist_ExpectCreated() throws Exception {
		CreateUserRequest request = new CreateUserRequest().username("user5").password("user5");
		mockMvc.perform(post(API_URL)
						.header(AUTHORIZATION, adminAccessToken())
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(status().isOk())
				.andDo((r -> {
					String contentAsString = r.getResponse().getContentAsString();
					UserDto response = assertDoesNotThrow(() -> objectMapper.readValue(contentAsString,
							UserDto.class));
					assertEquals(response.getUsername(), request.getUsername());
					List<RoleDto> roles = response.getRoles();
					assertEquals(1, roles.size());
					assertEquals(roles.get(0).getName(), DefaultRoles.USER.name());
				}));
		assertTrue(userRepository.existsByUsername(request.getUsername()));
	}

	@Test
	void createUser_WhenExists_Expect409() throws Exception {
		String username = "user6";
		String password = "user6";
		userService.createUser(username, password);
		CreateUserRequest request = new CreateUserRequest().username(username).password(password);
		mockMvc.perform(post(API_URL)
						.header(AUTHORIZATION, adminAccessToken())
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(status().isConflict());
	}

	@Test
	void changePassword_WhenOldMatch_ExpectChanged() throws Exception {
		String username = "user7";
		String password = "user7";
		String token = userAccessToken(username, password);
		ChangeUserPasswordRequest request = new ChangeUserPasswordRequest()
				.oldPassword(password)
				.newPassword("newPassword");
		mockMvc.perform(patch(API_URL)
						.header(AUTHORIZATION, token)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(status().isOk());
	}

	@Test
	void changePassword_WhenOldDontMatch_ExpectForbidden() throws Exception {
		String username = "user8";
		String password = "user8";
		String token = userAccessToken(username, password);
		ChangeUserPasswordRequest request = new ChangeUserPasswordRequest()
				.oldPassword("wrong")
				.newPassword("newPassword");
		mockMvc.perform(patch(API_URL)
						.header(AUTHORIZATION, token)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(status().isForbidden());
	}


	@Test
	void delete_Exists_ExpectDeleted() throws Exception {
		String username = "user9";
		String password = "user9";
		userService.createUser(username, password);
		mockMvc.perform(delete(API_URL + "/{username}", username)
						.header(AUTHORIZATION, adminAccessToken()))
				.andExpect(status().isOk());
	}

	@Test
	void delete_WhenNotSavedOne_ExpectNotFound() throws Exception {
		String username = "user10";
		mockMvc.perform(delete(API_URL + "/{username}", username)
						.header(AUTHORIZATION, adminAccessToken()))
				.andExpect(status().isNotFound());
	}

	@Test
	void getRoles_WhenUserCreated_ExpectDefault() throws Exception {
		String username = "user11";
		String password = "user11";
		userService.createUser(username, password);
		String token = adminAccessToken();
		mockMvc.perform(get(API_URL + "/{username}/role", username).header(AUTHORIZATION, token))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.[*]", hasSize(1)))
				.andExpect(jsonPath("$.[*].name", hasItem(equalTo(DefaultRoles.USER.name()))));

	}

	@Test
	void getRoles_WhenUserNotExists_ExpectNotFound() throws Exception {
		String username = "user12";
		String token = adminAccessToken();
		mockMvc.perform(get(API_URL + "/{username}/role", username).header(AUTHORIZATION, token))
				.andExpect(status().isNotFound());
	}

	@Test
	void assignRole_WhenUserNotExists_ExpectNotFound() throws Exception {
		String username = "user13";
		String roleName = "USER_13";
		String token = adminAccessToken();
		rolesService.createRole(roleName);
		List<RoleDto> request = createRoleDto(roleName);
		mockMvc.perform(post(API_URL + "/{username}/role/assign", username)
						.header(AUTHORIZATION, token)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(status().isNotFound());
	}

	@Test
	void assignRole_WhenUserExists_ExpectChanged() throws Exception {
		String username = "user14";
		String roleName = "USER_14";
		String token = adminAccessToken();
		userService.createUser(username, "user14");
		rolesService.createRole(roleName);
		List<RoleDto> request = createRoleDto(roleName);
		mockMvc.perform(post(API_URL + "/{username}/role/assign", username)
						.header(AUTHORIZATION, token)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.[*]", hasSize(2)))
				.andExpect(jsonPath("$.username").value(username))
				.andExpect(jsonPath("$.roles[*].name", hasItems(equalTo(DefaultRoles.USER.name()),
						equalTo(roleName))));
	}

	@Test
	void assignRole_WhenUserHasRole_ExpectNotChanged() throws Exception {
		String username = "user15";
		String token = adminAccessToken();
		userService.createUser(username, "user15");
		List<RoleDto> request = createRoleDto(DefaultRoles.USER.name());
		mockMvc.perform(post(API_URL + "/{username}/role/assign", username)
						.header(AUTHORIZATION, token)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(jsonPath("$.username").value(username))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.roles", hasSize(1)))
				.andExpect(jsonPath("$.roles[*].name", hasItems(equalTo(DefaultRoles.USER.name()))));
	}

	@Test
	void assignRole_WhenRoleNotExists_ExpectRoleNotFound() throws Exception {
		String username = "user16";
		String token = adminAccessToken();
		userService.createUser(username, "user16");
		List<RoleDto> request = createRoleDto("USER_16");
		mockMvc.perform(post(API_URL + "/{username}/role/assign", username)
						.header(AUTHORIZATION, token)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(status().isNotFound());
	}

	@Test
	void revokeRole_WhenUserNotExists_ExpectNotFound() throws Exception {
		String username = "user17";
		String roleName = "USER_17";
		String token = adminAccessToken();
		rolesService.createRole(roleName);
		List<RoleDto> request = createRoleDto(roleName);
		mockMvc.perform(post(API_URL + "/{username}/role/revoke", username)
						.header(AUTHORIZATION, token)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(status().isNotFound());
	}

	@Test
	void revokeRole_WhenUserHasRoleExists_ExpectChanged() throws Exception {
		String username = "user18";
		String roleName = "USER_18";
		String token = adminAccessToken();
		userService.createUser(username, "user18");
		rolesService.createRole(roleName);
		userService.assignRoles(username, List.of(roleName));
		List<RoleDto> request = createRoleDto(roleName);
		mockMvc.perform(post(API_URL + "/{username}/role/revoke", username)
						.header(AUTHORIZATION, token)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.username").value(username))
				.andExpect(jsonPath("$.roles", hasSize(1)))
				.andExpect(jsonPath("$.roles[*].name", hasItems(equalTo(DefaultRoles.USER.name()))));
	}

	@Test
	void revokeRole_WhenUserHasNotRole_ExpectNotChanged() throws Exception {
		String username = "user19";
		String roleName = "USER_19";
		String token = adminAccessToken();
		userService.createUser(username, "user19");
		rolesService.createRole(roleName);
		List<RoleDto> request = createRoleDto(roleName);
		mockMvc.perform(post(API_URL + "/{username}/role/revoke", username)
						.header(AUTHORIZATION, token)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.username").value(username))
				.andExpect(jsonPath("$.roles", hasSize(1)))
				.andExpect(jsonPath("$.roles[*].name", hasItems(equalTo(DefaultRoles.USER.name()))));
	}

	@Test
	void revokeRole_WhenRoleNotExists_ExpectNotChanged() throws Exception {
		String username = "user20";
		String token = adminAccessToken();
		userService.createUser(username, "user20");
		List<RoleDto> request = createRoleDto("USER_20");
		mockMvc.perform(post(API_URL + "/{username}/role/revoke", username)
						.header(AUTHORIZATION, token)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.username").value(username))
				.andExpect(jsonPath("$.roles", hasSize(1)))
				.andExpect(jsonPath("$.roles[*].name", hasItems(equalTo(DefaultRoles.USER.name()))));
	}


	private String adminAccessToken() {
		return "Bearer " + tokenProviderService.token("admin", "admin").getAccessToken();
	}

	private String userAccessToken(String userName, String password) {
		return "Bearer " + createUserAndToken(userName, password, List.of(DefaultRoles.USER.name())).getAccessToken();
	}

	private TokenResponse createUserAndToken(String username, String password, List<String> roles) {
		userService.createUser(username, password);
		userService.assignRoles(username, roles);
		return tokenProviderService.token(username, password);
	}

	private List<RoleDto> createRoleDto(String... names) {
		return Arrays.stream(names)
				.map(n -> new RoleDto().name(n))
				.toList();
	}

	;
}