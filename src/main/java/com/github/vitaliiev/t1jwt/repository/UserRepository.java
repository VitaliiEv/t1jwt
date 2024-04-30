package com.github.vitaliiev.t1jwt.repository;

import com.github.vitaliiev.t1jwt.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

	@EntityGraph("User.withRoles")
	Optional<User> findByUsername(String username);

	boolean existsByUsername(String username);

	@Modifying
	@Query("delete from User e where e.username = :username")
	int deleteByUsername(@Param("username") String username);

	@Override
	@EntityGraph("User.withRoles")
	Page<User> findAll(Pageable pageable);
}
