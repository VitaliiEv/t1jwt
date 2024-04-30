package com.github.vitaliiev.t1jwt.repository;

import com.github.vitaliiev.t1jwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {

	Optional<Role> findByName(String names);

	@Query("select r from Role r where r.name in :names")
	List<Role> findByNames(@Param("names") Collection<String> names);

	@Modifying
	@Query("delete from Role e where e.name = :name")
	int deleteByName(@Param("name") String name);

}
