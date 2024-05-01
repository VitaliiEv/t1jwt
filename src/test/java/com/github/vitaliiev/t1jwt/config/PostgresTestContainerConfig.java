package com.github.vitaliiev.t1jwt.config;


import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;

public class PostgresTestContainerConfig {


	private static final String PASSWORD = "postgres";
	private static final String USERNAME = "postgres";
	private static final int PORT = 5432;
	private static final String DATABASE_NAME = "t1jwt_test";

	@Container
	private final static PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15.4")
			.withDatabaseName(DATABASE_NAME)
			.withUsername(USERNAME)
			.withPassword(PASSWORD)
			.withExposedPorts(PORT);

	@DynamicPropertySource
	private static void registerPgProperties(DynamicPropertyRegistry registry) {
		registry.add("spring.datasource.url", () -> String.format("jdbc:postgresql://%s:%d/%s", POSTGRES.getHost(),
				POSTGRES.getFirstMappedPort(), POSTGRES.getDatabaseName()));
		registry.add("spring.datasource.username", () -> USERNAME);
		registry.add("spring.datasource.password", () -> PASSWORD);
	}

}
