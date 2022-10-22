package com.tpe.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.tpe.security.jwt.AuthTokenFilter;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
	
	
	   @Autowired
	   private UserDetailsService userDetailsService;

	    @Bean
	    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	    	
	    	http.csrf().disable().//disable etmezseniz POST Yapamazsınız
	    	sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().
	        authorizeRequests().
	        antMatchers("/","index.html","/css/*","/js/*","/images/*","/register","/login").permitAll().
	        //and().
	        //authorizeRequests().antMatchers("/student/**").hasRole("INSTRUCTOR").and().
	        //authorizeRequests().antMatchers("/beans/**").hasAuthority("ROLE_ADMIN").
//	        authorizeRequests().antMatchers("/beans/**").hasRole("ADMIN").
	        anyRequest().authenticated();
	        
	        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
	        
	        return http.build();
	    }
	    
	    
	    @Bean
	    public AuthTokenFilter authTokenFilter() {
	    	return new AuthTokenFilter();
	    } 
	    
	    
	    /*
	     * register->Kullanıcıdan aldığımız bilgiler, PasswordEncoder
	     * 
	     * token= login->username yada email,password->username'i doğrulamak(authenticationManager)  ve token generate 
	     * access a resource-> Filter'da yapılcak   (token-> parse, validate, user securitycontexte koyulacak, resource'a access edilecek)
	     */
	    
	    
	    @Bean
	    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
	    	return 
	    			http.getSharedObject(AuthenticationManagerBuilder.class)
	    			.authenticationProvider(authProvider()).build();
	    }
	    
	    
	    @Bean 
	    public DaoAuthenticationProvider authProvider() {
	    	DaoAuthenticationProvider authenticationProvider=new DaoAuthenticationProvider();
	    	authenticationProvider.setUserDetailsService(userDetailsService);
	    	authenticationProvider.setPasswordEncoder(passwordEncoder());
	    	return authenticationProvider;
	    }
	    
	    
	    
	    @Bean
	    public PasswordEncoder passwordEncoder() {
	    	return new BCryptPasswordEncoder(10);
	    }
	    
	
}
