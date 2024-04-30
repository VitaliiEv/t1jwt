package com.github.vitaliiev.t1jwt.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JWTConfigurer extends AbstractHttpConfigurer<JWTConfigurer, HttpSecurity> {

	@Override
	public void configure(HttpSecurity builder) {
		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
		AuthenticationConverter converter = new JWTAuthenticationConverter();
		AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager, converter);
		authenticationFilter.setSuccessHandler((request, response, authentication) -> {
		}); // noop, avoid redirect
		builder.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
	}
}
