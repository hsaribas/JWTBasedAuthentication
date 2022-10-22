package com.tpe.controller;

import javax.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.tpe.dto.request.LoginRequest;
import com.tpe.dto.request.RegisterRequest;
import com.tpe.dto.response.LoginResponse;
import com.tpe.dto.response.MyResponse;
import com.tpe.security.SecurityUtils;
import com.tpe.security.jwt.JwtUtils;
import com.tpe.service.UserService;

import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
public class UserJWTController {

	private UserService userService;

	private AuthenticationManager authenticationManager;

	private JwtUtils jwtUtils;
	
	
	@GetMapping("/welcome")
	public String welcome() {
		
		//UserDetails userDetails= (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
		String userName= SecurityUtils.getCurrentUserLogin().orElseThrow(()->new UsernameNotFoundException("Username not found:"));
		
		return "Welcome to secured area for User:"+userName;
	}

	@PostMapping("/register")
	public ResponseEntity<MyResponse> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
		userService.saveUser(registerRequest);

		MyResponse myResponse = new MyResponse("User registered successfully", true);
		return new ResponseEntity<>(myResponse, HttpStatus.CREATED);
	}

	@PostMapping("/login")
	public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
				loginRequest.getUserName(), loginRequest.getPassword());
		Authentication authenticated = authenticationManager.authenticate(authentication);

		// Currently logged in user
		UserDetails userDetails = (UserDetails) authenticated.getPrincipal();
		String token = jwtUtils.generateToken(userDetails);

		LoginResponse loginResponse = new LoginResponse(token);
		
		return new ResponseEntity<>(loginResponse, HttpStatus.CREATED);

	}

}
