package com.github.vitaliiev.t1jwt.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.vitaliiev.t1jwt.config.IntegrationTest;
import com.github.vitaliiev.t1jwt.model.RefreshTokenRequest;
import com.github.vitaliiev.t1jwt.model.TokenRequest;
import com.github.vitaliiev.t1jwt.model.TokenResponse;
import com.github.vitaliiev.t1jwt.model.User;
import com.github.vitaliiev.t1jwt.service.TokenProviderService;
import com.github.vitaliiev.t1jwt.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@IntegrationTest
class AuthApiImplTest {

	@Autowired
	private MockMvc mockMvc;
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private UserService userService;
	@Autowired
	private TokenProviderService tokenProviderService;

	private static final String API_URL_TOKEN = "/api/v1/auth/token";
	private static final String API_URL_REFRESH = "/api/v1/auth/refresh";

	@Test
	void token_WhenUserExists_ExpectTokenResponse() throws Exception {
		String username = "user1";
		String password = "password";
		User user = userService.createUser(username, password);
		TokenRequest tokenRequest = new TokenRequest()
				.username(user.getUsername())
				.password(password);
		mockMvc.perform(post(API_URL_TOKEN)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(tokenRequest)))
				.andExpect(status().isOk())
				.andDo((r -> {
					String contentAsString = r.getResponse().getContentAsString();
					TokenResponse response = assertDoesNotThrow(() -> objectMapper.readValue(contentAsString,
							TokenResponse.class));
					assertNotNull(response.getAccessToken());
					assertNotNull(response.getRefreshToken());
				}));
	}

	@Test
	void refresh_WhenIssued_ExpectTokenResponse() throws Exception {
		String username = "user2";
		String password = "password";
		User user = userService.createUser(username, password);
		TokenResponse token = tokenProviderService.token(username, password);
		RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest()
				.refreshToken(token.getRefreshToken());
		mockMvc.perform(post(API_URL_REFRESH)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(refreshTokenRequest)))
				.andExpect(status().isOk())
				.andDo((r -> {
					String contentAsString = r.getResponse().getContentAsString();
					TokenResponse response = assertDoesNotThrow(() -> objectMapper.readValue(contentAsString,
							TokenResponse.class));
					assertNotNull(response.getAccessToken());
					assertNotNull(response.getRefreshToken());
				}));
	}
}