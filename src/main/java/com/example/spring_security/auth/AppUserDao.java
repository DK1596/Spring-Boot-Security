package com.example.spring_security.auth;

import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AppUserDao {

    Optional<AppUser> selectAppUserByUsername(String username);
}
