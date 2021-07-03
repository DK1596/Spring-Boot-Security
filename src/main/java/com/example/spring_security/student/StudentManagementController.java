package com.example.spring_security.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Tom Marry"),
            new Student(2, "Anna Perry"),
            new Student(3, "Fill Richards"));

    // PreAuthorize = hasRole/anyRole('ROLE_'), hasAuthority/anyAuthority('permission')
    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMIN_TRAINEE')")
    public List<Student> getAll(){
        System.out.println("getAll");
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void register(@RequestBody Student student){
        System.out.println("register");
        System.out.println(student);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('student:write')")
    public void delete(@PathVariable("id") Integer id){
        System.out.println("delete");
        System.out.println(id);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('student:write')")
    public void update(@PathVariable("id")Integer id, @RequestBody Student student){
        System.out.println("update");
        System.out.println(String.format("%d, %s", id, student));
    }
}
