package com.github.vitaliiev.t1jwt.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "application.jwt", ignoreUnknownFields = false)
public class JwtProperties {

	@NotNull
	@NotBlank
	private String secretKey;

	@Positive
	private int tokenValiditySeconds = 3600; // default 1 hour

	@Positive
	private int refreshTokenValiditySeconds = 86400;// default 24 hours
}
