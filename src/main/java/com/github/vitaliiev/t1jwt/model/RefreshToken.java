package com.github.vitaliiev.t1jwt.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Getter
@Setter
public class RefreshToken {

	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	private UUID id;
	
	@NotNull
	@Column(nullable = false)
	private Instant createdAt;

	@NotNull
	@OneToOne
	@JoinColumn(nullable = false, unique = true)
	private User user;

}
