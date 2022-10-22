package com.tpe.service;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.tpe.domain.Role;
import com.tpe.domain.User;
import com.tpe.domain.enums.RoleType;
import com.tpe.dto.request.RegisterRequest;
import com.tpe.repository.UserRepository;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class UserService {

	
	private UserRepository userRepository;
	
	private PasswordEncoder passwordEncoder;
	
	private RoleService roleService;
	
	public void saveUser(RegisterRequest  registerRequest) {
		User myUser=new User();
		
		myUser.setFirstName(registerRequest.getFirstName());
		myUser.setLastName(registerRequest.getLastName());
		myUser.setUserName(registerRequest.getUserName());
		
		String password = registerRequest.getPassword();
		
		//
		String encodedPassword=passwordEncoder.encode(password);
		myUser.setPassword(encodedPassword);
		
		//ROLE must be set
		Role role=roleService.getRoleByType(RoleType.ROLE_INSTRUCTOR);
		Set<Role> roles=new HashSet<>();
		roles.add(role);
		
		myUser.setRoles(roles);
		
		userRepository.save(myUser);
	}
	
	
	
}
