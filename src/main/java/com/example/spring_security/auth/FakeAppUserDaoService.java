package com.example.spring_security.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.spring_security.security.UserRole.*;

@Repository("fake")
public class FakeAppUserDaoService implements AppUserDao{

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeAppUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<AppUser> selectAppUserByUsername(String username) {
        return getAppUsers().stream()
                .filter(appUser -> username.equals(appUser.getUsername()))
                .findFirst();
    }

    private List<AppUser> getAppUsers(){
        List<AppUser> appUsers = Lists.newArrayList(
                new AppUser(STUDENT.getGrantedAuthorities(),
                        "anna",
                        passwordEncoder.encode("password"),
                        true,
                        true,
                        true,
                        true),
                new AppUser(ADMIN.getGrantedAuthorities(),
                        "linda",
                        passwordEncoder.encode("password"),
                        true,
                        true,
                        true,
                        true),
                new AppUser(ADMIN_TRAINEE.getGrantedAuthorities(),
                        "tom",
                        passwordEncoder.encode("password"),
                        true,
                        true,
                        true,
                        true)
        );
        return appUsers;
    }
}
