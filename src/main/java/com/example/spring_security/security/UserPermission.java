package com.example.spring_security.security;

public enum UserPermission {
    STUDENT_WRITE("student:write"),
    STUDENT_READ("student:read"),
    COURSE_WRITE("course:write"),
    COURSE_READ("course:read");

    private final String PERMISSION;

    UserPermission(String PERMISSION) {
        this.PERMISSION = PERMISSION;
    }

    public String getPERMISSION() {
        return PERMISSION;
    }
}
