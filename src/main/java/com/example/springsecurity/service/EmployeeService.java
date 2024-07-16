package com.example.springsecurity.service;

import com.example.springsecurity.entity.Employee;
import com.example.springsecurity.repository.EmployeeRepo;
import org.springframework.stereotype.Service;

@Service
public class EmployeeService {
    private final EmployeeRepo employeeRepo;

    public EmployeeService(EmployeeRepo employeeRepo) {
        this.employeeRepo = employeeRepo;
    }

    public Employee getEmployee(Long employeeId) {
        return employeeRepo.findById(employeeId).get();
    }

    public Employee addNewEmployee(Employee employee) {
        return employeeRepo.save(employee);
    }
}
