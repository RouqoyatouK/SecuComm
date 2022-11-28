package com.securite.springjwt.security.services;


import com.securite.springjwt.models.User;

import java.util.List;

public interface UserService {

    List<User> lire();
    String supprimer (Long id);
    User modif(Long id, User user);

    /*List<User> lire();
    String supprimer (Long id);
    User modif(Long id, U user);*/
}
