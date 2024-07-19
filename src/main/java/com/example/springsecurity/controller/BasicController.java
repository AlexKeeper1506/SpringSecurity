package com.example.springsecurity.controller;

import com.example.springsecurity.user.TestUser;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;

@RestController
public class BasicController {
    private final JdbcUserDetailsManager userManager;
    private final PasswordEncoder passwordEncoder;

    public BasicController(JdbcUserDetailsManager userManager, PasswordEncoder passwordEncoder) {
        this.userManager = userManager;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/")
    public String defaultPage() {
        return "Default page!";
    }

    @GetMapping("/welcome")
    public String welcomeAlex() {
        return "Welcome, Alex!";
    }

    @GetMapping("/route1")
    @PreAuthorize("hasAuthority('PERMISSION_ROUTE1')")
    public String route1() {
        return "You're on route1";
    }

    @GetMapping("/route2")
    @PreAuthorize("hasAuthority('PERMISSION_ROUTE2')")
    public String route2() {
        return "You're on route2";
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

    @GetMapping("/foo2")
    public String foo2(@RequestParam String password) {
        return passwordEncoder.encode(password);
    }

    @GetMapping("/create_users")
    //@PreAuthorize("hasRole('ADMIN')")
    public String createUsers() {
        try {
            final TestUser testUser = new TestUser(passwordEncoder);
            System.out.println(testUser.getPassword());
            userManager.createUser(testUser);
            return "Success!";
        } catch (Exception exception) {
            return "Failure!";
        }
    }
}
