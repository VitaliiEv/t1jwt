plugins {
	java
	id("org.springframework.boot") version "3.2.5"
	id("io.spring.dependency-management") version "1.1.4"
	id("org.openapi.generator") version "7.5.0"
}

group = "com.github.vitaliiev"
version = "0.0.1-SNAPSHOT"

extra["springdocOpenapiVersion"] = "2.5.0"
extra["jjwtVersion"] = "0.12.5"

java {
	sourceCompatibility = JavaVersion.VERSION_17
}

configurations {
	compileOnly {
		extendsFrom(configurations.annotationProcessor.get())
	}
}

repositories {
	mavenCentral()
}

dependencies {
	implementation("org.springframework.boot:spring-boot-starter")
	implementation("org.springframework.boot:spring-boot-starter-data-jpa")
	implementation("org.springframework.boot:spring-boot-starter-validation")
	implementation("org.springframework.boot:spring-boot-starter-web")
	implementation("org.springframework.boot:spring-boot-starter-security")

	implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:${property("springdocOpenapiVersion")}")
	runtimeOnly("org.postgresql:postgresql")
	runtimeOnly("io.jsonwebtoken:jjwt-jackson:${property("jjwtVersion")}")
	runtimeOnly("io.jsonwebtoken:jjwt-impl:${property("jjwtVersion")}")

	compileOnly("io.jsonwebtoken:jjwt-api:${property("jjwtVersion")}")
	compileOnly("org.projectlombok:lombok")

	annotationProcessor("org.projectlombok:lombok")

	testImplementation("org.springframework.boot:spring-boot-starter-test")
	testImplementation("org.testcontainers:junit-jupiter")
	testImplementation("org.testcontainers:postgresql")
	testImplementation("org.springframework.boot:spring-boot-testcontainers")
	testImplementation("org.springframework.security:spring-security-test")
	testAnnotationProcessor("org.projectlombok:lombok")

}

tasks.withType<Test> {
	useJUnitPlatform()
}

val projectBuildDir = layout.buildDirectory.asFile.get();
val openApiOutputDir = "$projectBuildDir/generated"

sourceSets {
	main {
		java.srcDir("$openApiOutputDir/src/main/java")
	}
}

openApiGenerate {
	generatorName = "spring"
	inputSpec = "$rootDir/src/main/resources/api.yaml"
	outputDir = openApiOutputDir
	apiPackage = "com.github.vitaliiev.t1jwt.api"
	modelPackage = "com.github.vitaliiev.t1jwt.model"
	apiFilesConstrainedTo.add("")
	modelFilesConstrainedTo.add("")
	supportingFilesConstrainedTo.add("ApiUtil.java")
	configOptions = mapOf(
		"delegatePattern" to "true",
		"title" to "t1aspect",
		"useJakartaEe" to "true",
		"openApiNullable" to "false",
	)

	validateSpec = true

	typeMappings = mapOf(
		"OffsetDateTime" to "java.time.LocalDateTime"
	)
	// Spring Boot 3 fix
	importMappings = mapOf(
		"ParameterObject" to "org.springdoc.core.annotations.ParameterObject"
	)
}

tasks.compileJava {
	dependsOn("openApiGenerate")
}