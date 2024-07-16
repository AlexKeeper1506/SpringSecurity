package com.example.springsecurity.controller;

import com.example.springsecurity.entity.Employee;
import com.example.springsecurity.service.EmployeeService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/employee")
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
    public String findEmployee() {
        return "Welcome, Alex!";
    }

    @PostMapping("/create")
    public Employee createEmployee(@RequestBody Employee employee) {
        return employeeService.addNewEmployee(employee);
    }
}
