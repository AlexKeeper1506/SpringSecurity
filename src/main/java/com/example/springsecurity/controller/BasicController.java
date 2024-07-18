package com.example.springsecurity.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class BasicController {
    @GetMapping("/")
    public String defaultPage() {
        return "Default page!";
    }

    @GetMapping("/welcome")
    public String welcomeAlex() {
        return "Welcome, Alex!";
    }

    @GetMapping("/admin")
    public String welcomeAdmin() {
        return "Welcome, admin!";
    }

    @GetMapping("/admin2")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String welcomeAdmin2() {
        return "Welcome, another admin!";
    }

    @GetMapping("/user")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String welcomeUser() {
        return "Welcome, user!";
    }

    @GetMapping("/foo")
    public String foo(HttpServletRequest request) {
        String operator = request.getHeader("operator");
        return "hello, " + operator;
    }
}
