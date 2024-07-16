package com.example.springsecurity.repository;

import com.example.springsecurity.entity.Employee;
import org.springframework.data.repository.CrudRepository;

public interface EmployeeRepo extends CrudRepository<Employee, Long> {
}
