package com.github.vitaliiev.t1jwt.config;

import com.github.vitaliiev.t1jwt.security.DefaultRoles;
import com.github.vitaliiev.t1jwt.security.JWTAuthenticationProvider;
import com.github.vitaliiev.t1jwt.security.JWTConfigurer;
import com.github.vitaliiev.t1jwt.service.TokenValidatorService;
import com.github.vitaliiev.t1jwt.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.http.HttpMethod.*;

@EnableMethodSecurity
@Configuration
public class SecurityConfig {

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
		SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();
		simpleAuthorityMapper.setConvertToUpperCase(true);
		return simpleAuthorityMapper;
	}

	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider(PasswordEncoder passwordEncoder,
	                                                           UserService userService,
	                                                           GrantedAuthoritiesMapper grantedAuthoritiesMapper) {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setPasswordEncoder(passwordEncoder);
		authenticationProvider.setUserDetailsService(userService);
//		authenticationProvider.setUserDetailsPasswordService(userService);
		authenticationProvider.setAuthoritiesMapper(grantedAuthoritiesMapper);
		return authenticationProvider;
	}

	@Bean
	public AuthenticationProvider jwtAuthenticationProvider(TokenValidatorService tokenValidatorService,
	                                                        GrantedAuthoritiesMapper grantedAuthoritiesMapper) {
		JWTAuthenticationProvider jwtAuthenticationProvider = new JWTAuthenticationProvider(tokenValidatorService);
		jwtAuthenticationProvider.setAuthoritiesMapper(grantedAuthoritiesMapper);
		return jwtAuthenticationProvider;
	}

	@Bean
	@Order(1)
	public SecurityFilterChain authFilterChain2(HttpSecurity http) throws Exception {

		return http
				.csrf(AbstractHttpConfigurer::disable)
				.securityMatchers(matchers -> matchers.requestMatchers("/api/v1/auth/**"))
				.authorizeHttpRequests(auth -> auth.requestMatchers("/api/v1/auth/**").permitAll())
				.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain apiFilterChain(HttpSecurity http, AuthenticationProvider jwtAuthenticationProvider) throws Exception {
		String admin = DefaultRoles.ADMIN.name();
		String user = DefaultRoles.USER.name();
		return http
				.csrf(AbstractHttpConfigurer::disable)
				.securityMatchers(matchers -> matchers.requestMatchers("/api/v1/**", "/**"))
				.authorizeHttpRequests(auth -> auth
//						.requestMatchers("/api/v1/**", "/**").authenticated()
						.requestMatchers(GET, "/api/v1/user/*", "/api/v1/user/*/role").hasAnyRole(admin, user)
						.requestMatchers(PATCH, "/api/v1/user").hasAnyRole(admin, user)
						.requestMatchers(POST, "/api/v1/user").hasRole(admin)
						.requestMatchers(DELETE, "/api/v1/user/*").hasRole(admin)
						.requestMatchers("/**", "/api/v1/**", "/api/v1/user",
								"/api/v1/role/**", "/api/v1/user/*/role/**").hasRole(admin)
						.anyRequest().denyAll())
				.authenticationProvider(jwtAuthenticationProvider)
				.with(new JWTConfigurer(), Customizer.withDefaults())
				.build();
	}

}
