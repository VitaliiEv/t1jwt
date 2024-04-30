package com.github.vitaliiev.t1jwt.repository;

import com.github.vitaliiev.t1jwt.model.RefreshToken;
import com.github.vitaliiev.t1jwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

	@Query("select e from RefreshToken e where e.user.username = :username")
	Optional<RefreshToken> findByUsername(@Param("username") String username);

	@Modifying
	@Query("delete from RefreshToken e where e.user = :user")
	void deleteByUser(@Param("user") User user);
}
