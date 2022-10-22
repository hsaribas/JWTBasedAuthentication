package com.tpe.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tpe.domain.Role;
import com.tpe.domain.enums.RoleType;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {

	Optional<Role> findByType(RoleType type);
	
}
