package com.securite.springjwt.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.securite.springjwt.models.User;
import com.securite.springjwt.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

  /*L'interface a une méthode pour charger l'utilisateur par nom d' utilisateur et renvoie
  un UserDetailsobjet que Spring Security peut utiliser pour l'authentification et la validation.*/
  @Autowired
  UserRepository userRepository;

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

    return UserDetailsImpl.build(user);
  }

}
