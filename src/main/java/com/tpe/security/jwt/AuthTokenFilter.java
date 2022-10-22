package com.tpe.security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

public class AuthTokenFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtils jwtUtils;

	@Autowired
	private UserDetailsService userDetailsService;

	private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String jwtToken = parseJwt(request);

		try {
			if (jwtToken != null && jwtUtils.validateToken(jwtToken)) {
				String userName = jwtUtils.getUserNameFromJwtToken(jwtToken);
				UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				
//				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
//						userDetails.getUsername(), null, userDetails.getAuthorities());

				//resource'lara erişirken authenticated user bilgisi ihtiyaç duyulduğunda SecurityContextHolder'dan User bilgisini çekebilmek için
				SecurityContextHolder.getContext().setAuthentication(authentication);

			}
		} catch (Exception e) {
			logger.error("User Not Found {}", e.getMessage());
		}

		filterChain.doFilter(request, response);

	}

	// Token'ı Authorization header içinden parse ettik
	/*
	 * Bearer eyJhbGciOiJIUzUxMiJ9.
	 * eyJzdWIiOiJicnVjZSIsImlhdCI6MTY2NTgzNjE0MiwiZXhwIjoxNjY1OTIyNTQyfQ.
	 * qfHgJxWISnoWV234OcD3r2kq4n4Kz-
	 * FamGlE75SYGjQDwbDh6pgxASBQYXlLY8BbPYm7rB0SoZ4Tuv4M40GuPw
	 */
	private String parseJwt(HttpServletRequest request) {
		String header = request.getHeader("Authorization");

		if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
			return header.substring(7);
		}
		return null;

	}
	
	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		//register, login
		AntPathMatcher antPathMatcher=new AntPathMatcher();
		
		return antPathMatcher.match("/register", request.getServletPath())||
				antPathMatcher.match("/login", request.getServletPath());
	}
	
	

}
