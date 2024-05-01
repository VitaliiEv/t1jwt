package com.github.vitaliiev.t1jwt.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

@Configuration
// https://github.com/OpenAPITools/openapi-generator/issues/12220
@OpenAPIDefinition(
		info = @Info(title = "User management API", description = "User management API", version = "0.0.1")
)
//https://github.com/OpenAPITools/openapi-generator/issues/457
//https://openapi-generator.tech/docs/generators/spring/#security-feature
@SecurityScheme(
		name = "jwt",
		type = SecuritySchemeType.HTTP,
		bearerFormat = "JWT",
		scheme = "bearer",
		in = SecuritySchemeIn.HEADER
)
public class OpenApiConfiguration {
}
