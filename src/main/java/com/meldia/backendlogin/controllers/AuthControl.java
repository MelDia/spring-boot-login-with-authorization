package com.meldia.backendlogin.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.meldia.backendlogin.models.ERole;
import com.meldia.backendlogin.models.Role;
import com.meldia.backendlogin.models.User;
import com.meldia.backendlogin.payload.request.LoginRequest;
import com.meldia.backendlogin.payload.request.SignupRequest;
import com.meldia.backendlogin.payload.response.JwtResponse;
import com.meldia.backendlogin.payload.response.MessageResponse;
import com.meldia.backendlogin.repository.RoleRepository;
import com.meldia.backendlogin.repository.UserRepository;
import com.meldia.backendlogin.security.jwt.JwtUtil;
import com.meldia.backendlogin.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthControl {

	@Autowired
	AuthenticationManager authManager;

	@Autowired
	UserRepository userRep;

	@Autowired
	RoleRepository roleRep;

	@Autowired
	PasswordEncoder encoder;
	
	@Autowired
	JwtUtil jwtUtil;

	//Sign in
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest login) {

		Authentication auth = authManager
				.authenticate(new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(auth);
		
		String jwt = jwtUtil.generateJwtTok(auth);

		UserDetailsImpl userDetails = (UserDetailsImpl) auth.getPrincipal();

		//ResponseCookie jwtCookie = jwtUtil.generateJwtCookie(userDetails);

		List<String> roles = userDetails.getAuthorities()
				.stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());
				
		return ResponseEntity.ok(new JwtResponse(jwt, 
                userDetails.getId(), 
                userDetails.getUsername(), 
                userDetails.getEmail(), 
                roles));

//		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString()).body(
//				new UserInfoResponse(userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));

	}

	//Register
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		if (userRep.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity
					.badRequest().
					body(new MessageResponse("Error: Username is already taken!", "IS NOT OK"));
		}

		if (userRep.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use!", "IS NOT OK"));
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(), // username
				signUpRequest.getEmail(), // email
				//signUpRequest.getPassword());
				encoder.encode(signUpRequest.getPassword())); //password
		System.out.println("USER ->" + user);

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		if (strRoles == null) {
			Role userRole = roleRep.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRep.findByName(ERole.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);

					break;
				case "mod":
					Role modRole = roleRep.findByName(ERole.ROLE_MODERATOR)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(modRole);

					break;
				default:
					Role userRole = roleRep.findByName(ERole.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRep.save(user);

		return ResponseEntity.ok(new MessageResponse("User registered successfully!", "OK"));
	}

	//Log out
	@PostMapping("/signout")
	public ResponseEntity<?> logoutUser() {
		ResponseCookie cookie = jwtUtil.getCleanJwtCookie();
		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
				.body(new MessageResponse("You've been signed out!", "OK"));
	}

}
