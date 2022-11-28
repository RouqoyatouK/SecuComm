package com.securite.springjwt.security.services;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.securite.springjwt.models.User;
import com.fasterxml.jackson.annotation.JsonIgnore;

public class UserDetailsImpl implements UserDetails {

  /*UserDetailscontient les informations nécessaires (telles que : nom d'utilisateur, mot de passe, autorités)
          pour construire un objet d'authentification.*/

  /*l'interface publique UserDetails
étend Serializable
Fournit des informations utilisateur de base.
Les implémentations ne sont pas utilisées directement par Spring Security
à des fins de sécurité. Ils stockent simplement des informations utilisateur
 qui sont ensuite encapsulées dans des Authentication objets. Cela permet aux
 informations utilisateur non liées à la sécurité (telles que les adresses e-mail,
les numéros de téléphone, etc.) d'être stockées dans un emplacement pratique.*/


  private static final long serialVersionUID = 1L;

  private Long id;

  private String username;

  private String email;

  @JsonIgnore
  private String password;

  private Collection<? extends GrantedAuthority> authorities;

  public UserDetailsImpl(Long id, String username, String email, String password,
      Collection<? extends GrantedAuthority> authorities) {
    //Renvoie les droits accordés à l'utilisateur. Impossible de revenir null.
    this.id = id;
    this.username = username;
    this.email = email;
    this.password = password;
    this.authorities = authorities;
  }

  public static UserDetailsImpl build(User user) {
    List<GrantedAuthority> authorities = user.getRoles().stream()
        .map(role -> new SimpleGrantedAuthority(role.getName().name()))
        .collect(Collectors.toList());

    return new UserDetailsImpl(
        user.getId(), 
        user.getUsername(), 
        user.getEmail(),
        user.getPassword(), 
        authorities);
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authorities;
  }

  public Long getId() {
    return id;
  }

  public String getEmail() {
    return email;
  }

  @Override
  public String getPassword() {
    return password;
    //Renvoie le mot de passe utilisé pour authentifier l'utilisateur.
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;

    //Indique si le compte de l'utilisateur a expiré.
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
    //Indique si l'utilisateur est verrouillé ou déverrouillé.
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
    //Indique si les informations d'identification de l'utilisateur (mot de passe) ont expiré.
  }

  @Override
  public boolean isEnabled() {
    return true;
    //Indique si l'utilisateur est activé ou désactivé.
  }

  @Override
  public boolean equals(Object o) {
    if (this == o)
      return true;
    if (o == null || getClass() != o.getClass())
      return false;
    UserDetailsImpl user = (UserDetailsImpl) o;
    return Objects.equals(id, user.id);
  }
}
