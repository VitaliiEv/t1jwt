package com.github.vitaliiev.t1jwt.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.vitaliiev.t1jwt.config.IntegrationTest;
import com.github.vitaliiev.t1jwt.model.RoleDto;
import com.github.vitaliiev.t1jwt.model.TokenResponse;
import com.github.vitaliiev.t1jwt.repository.RoleRepository;
import com.github.vitaliiev.t1jwt.security.DefaultRoles;
import com.github.vitaliiev.t1jwt.security.SecurityUtils;
import com.github.vitaliiev.t1jwt.service.RolesService;
import com.github.vitaliiev.t1jwt.service.TokenProviderService;
import com.github.vitaliiev.t1jwt.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@IntegrationTest
class RoleApiImplTest {

	@Autowired
	private MockMvc mockMvc;
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private UserService userService;
	@Autowired
	private RolesService rolesService;
	@Autowired
	private RoleRepository roleRepository;
	@Autowired
	private TokenProviderService tokenProviderService;

	private static final String API_URL = "/api/v1/role";

	@Test
	void createRole_WhenNotExist_ExpectSuccess() throws Exception {
		String roleName = "role1";
		RoleDto roleDto = new RoleDto()
				.name(roleName);
		String token = adminAccessToken("admin1", "admin1");
		mockMvc.perform(post(API_URL)
						.header(AUTHORIZATION, token)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(roleDto)))
				.andExpect(status().isOk())
				.andDo((r -> {
					String contentAsString = r.getResponse().getContentAsString();
					RoleDto response = assertDoesNotThrow(() -> objectMapper.readValue(contentAsString,
							RoleDto.class));
					assertEquals(response.getName(), SecurityUtils.removeRolePrefix(roleName));
				}));
		assertTrue(roleRepository.findByName(SecurityUtils.removeRolePrefix(roleName)).isPresent());
	}

	@Test
	void createRole_WhenExecutedWithUserScope_ExpectAccessDenied() throws Exception {
		String roleName = "role2";
		RoleDto roleDto = new RoleDto()
				.name(roleName);
		TokenResponse token = createToken("user2", "user2", List.of(DefaultRoles.USER.name()));
		mockMvc.perform(post(API_URL)
						.header(AUTHORIZATION, "Bearer " + token.getAccessToken())
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(roleDto)))
				.andExpect(status().isForbidden());
		assertTrue(roleRepository.findByName(SecurityUtils.removeRolePrefix(roleName)).isEmpty());
	}

	@Test
	void getRoles_WhenSavedOne_ExpectOne() throws Exception {
		String roleName = "role3";
		rolesService.createRole(roleName);
		String token = adminAccessToken("admin3", "admin3");
		mockMvc.perform(get(API_URL).header(AUTHORIZATION, token))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.[*]", hasSize(3)))
				.andExpect(jsonPath("$.[*].name", hasItem(equalTo(SecurityUtils.removeRolePrefix(roleName)))));
	}

	@Test
	void getRole_WhenSavedOne_ExpectOne() throws Exception {
		String roleName = "role4";
		rolesService.createRole(roleName);
		String token = adminAccessToken("admin4", "admin4");
		mockMvc.perform(get(API_URL + "/{rolename}", roleName).header(AUTHORIZATION, token))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andDo(r -> {
					String contentAsString = r.getResponse().getContentAsString();
					RoleDto t = assertDoesNotThrow(() -> objectMapper.readValue(contentAsString, RoleDto.class));
					assertEquals(t.getName(), SecurityUtils.removeRolePrefix(roleName));
				});
	}

	@Test
	void deleteRole_WhenSavedOne_ExpectDeleted() throws Exception {
		String roleName = "role5";
		rolesService.createRole(roleName);
		mockMvc.perform(delete(API_URL + "/{rolename}", roleName)
						.header(AUTHORIZATION, adminAccessToken("admin5", "admin5")))
				.andExpect(status().isOk());
		assertTrue(roleRepository.findByName(roleName).isEmpty());
	}

	@Test
	void deleteRole_WhenNotSavedOne_ExpectNotFound() throws Exception {
		String roleName = "role6";
		mockMvc.perform(delete(API_URL + "/{rolename}", roleName)
						.header(AUTHORIZATION, adminAccessToken("admin5", "admin5")))
				.andExpect(status().isNotFound());
	}

	private String adminAccessToken(String userName, String password) {
		return "Bearer " + createToken(userName, password, List.of(DefaultRoles.ADMIN.name())).getAccessToken();

	}

	private TokenResponse createToken(String username, String password, List<String> roles) {
		userService.createUser(username, password);
		userService.assignRoles(username, roles);
		return tokenProviderService.token(username, password);
	}


}