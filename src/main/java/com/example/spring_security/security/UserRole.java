package com.example.spring_security.security;

import com.google.common.collect.Sets;

import java.util.Set;

import static com.example.spring_security.security.UserPermission.*;

public enum UserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE));

    private final Set<UserPermission> PERMISSION;

    UserRole(Set<UserPermission> permission) {
        PERMISSION = permission;
    }

    public Set<UserPermission> getPERMISSION() {
        return PERMISSION;
    }
}
