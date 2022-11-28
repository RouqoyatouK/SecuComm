package com.securite.springjwt.security.services;

import com.securite.springjwt.models.User;
import com.securite.springjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
public class UserServiceImpl implements UserService{

    @Autowired
    UserRepository userRepository;

    @Override
    public List<User> lire() {
        return userRepository.findAll();
    }

    @Override
    public String supprimer(Long id) {
      //  log.info("suppression {} ",id);
         this.userRepository.deleteById(id);
        return "Ok";
    }

    @Override
    public User modif(Long id, User user) {
        return userRepository.findById(id).map(u->{
            u.setEmail(user.getEmail());
            u.setPassword((user.getPassword()));
            u.setUsername(user.getUsername());
            u.setRoles(user.getRoles());
            return  userRepository.save(u);
        }).orElseThrow(() -> new RuntimeException("utilisateur trouvé"));
    }

}

