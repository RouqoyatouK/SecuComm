package com.securite.springjwt.controllers;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import com.securite.springjwt.security.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.securite.springjwt.models.ERole;
import com.securite.springjwt.models.Role;
import com.securite.springjwt.models.User;
import com.securite.springjwt.payload.request.LoginRequest;
import com.securite.springjwt.payload.request.SignupRequest;
import com.securite.springjwt.payload.response.JwtResponse;
import com.securite.springjwt.payload.response.MessageResponse;
import com.securite.springjwt.repository.RoleRepository;
import com.securite.springjwt.repository.UserRepository;
import com.securite.springjwt.security.jwt.JwtUtils;
import com.securite.springjwt.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @Autowired
  UserService userService;



  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

    ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    List<String> rooool= new ArrayList<>();

    rooool.add("ROLE_USER");

    if (roles.equals(rooool)){
      return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString()).body("Hello User");
    }
    else
      return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString()).body("Hello , Hello User");


       /* return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));*/
  }

  @PostMapping("/signup")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user's account
    User user = new User(signUpRequest.getUsername(), 
               signUpRequest.getEmail(),
               encoder.encode(signUpRequest.getPassword()));

    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {

      Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(adminRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
        case "admin":
          Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(adminRole);

          break;

        default:
          Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

//afficher tout les user
  @GetMapping("/read")
  //@PostAuthorize("hasRole('USER') or hasRole('ADMIN')")
  public List<User> read() {
    return userRepository.findAll();

  }
//modif
  @PutMapping("/update/{id}")
  @PostAuthorize("hasRole('ADMIN')")
  public User update(@PathVariable Long id, @RequestBody User user) {
    return userService.modif(id, user);
  }
  //sup

  @DeleteMapping("/delete/{id}")
  @PostAuthorize("hasRole('ADMIN')")
  public String delete(@PathVariable Long id ) {
    Object ess = null;
    if (id.equals(ess)) return "ce utilisateur n'existe  pas";
    else
    return userService.supprimer(id);
  }
}
