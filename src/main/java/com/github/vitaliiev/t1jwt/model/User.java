package com.github.vitaliiev.t1jwt.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Getter
@Setter
@Table(name = "APP_USER")
@NamedEntityGraph(name = "User.withRoles", attributeNodes = {@NamedAttributeNode("roles")})
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	private UUID id;

	@NotNull
	@NotEmpty
	@Column(nullable = false, updatable = false, unique = true)
	private String username;

	@NotNull
	@Column(nullable = false)
	private String password;

	@ManyToMany(fetch = FetchType.EAGER)
	private List<Role> roles = new ArrayList<>();
}
