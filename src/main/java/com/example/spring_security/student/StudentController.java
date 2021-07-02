package com.example.spring_security.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Tom Marry"),
            new Student(2, "Katty Perry"),
            new Student(3, "Fill Richards"));

    @GetMapping("/{id}")
    public Student getStudent(@PathVariable("id") Integer id){
        return STUDENTS.stream()
                .filter(student -> id.equals(student.getId()))
                .findFirst().orElseThrow(() -> new IllegalStateException(
                        "Student with " + id + " not found"));
    }
}
