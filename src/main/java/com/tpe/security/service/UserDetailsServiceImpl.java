package com.tpe.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.tpe.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	@Autowired
	private UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		com.tpe.domain.User myUser= userRepository.findByUserName(username).orElseThrow(()->new UsernameNotFoundException("User not found:"+username));
		//myUser->UserDetails
		
		//Amaç: Bir adet UserDetails oluşturmak
		return UserDetailsImpl.build(myUser);
		
	}
	

}
