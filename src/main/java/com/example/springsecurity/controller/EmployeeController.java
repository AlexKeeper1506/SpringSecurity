package com.example.springsecurity.controller;

import com.example.springsecurity.entity.Employee;
import com.example.springsecurity.service.EmployeeService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class EmployeeController {
    private final EmployeeService employeeService;

    public EmployeeController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    @GetMapping("/find/{employeeId}")
    public Employee findEmployee(@PathVariable Long employeeId) {
        return employeeService.getEmployee(employeeId);
    }

    @GetMapping("/welcome")
    public String welcomeAlex() {
        return "Welcome, Alex!";
    }

    @GetMapping("/default")
    public String defaultPage() {
        return "Default page!";
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

    @GetMapping("/foo")
    public String foo(HttpServletRequest request) {
        String operator = request.getHeader("operator");
        return "hello, " + operator;
    }

    @PostMapping("/create")
    public Employee createEmployee(@RequestBody Employee employee) {
        return employeeService.addNewEmployee(employee);
    }
}
