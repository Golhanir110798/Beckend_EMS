package com.example.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.entity.Employee;
import com.example.exception.EmployeeNotFoundException;
import com.example.exception.ResourceNotFoundException;
import com.example.repository.EmployeeRepository;

@Service
public class EmployeeService {

	@Autowired
	private EmployeeRepository repository;
	
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


	public Employee createEmployee(Employee emp) {
		// TODO Auto-generated method stub
		emp.setPassword(passwordEncoder.encode(emp.getPassword()));
		Employee savedEmployee = repository.save(emp);
		return savedEmployee;
	}


	public Employee getEmployee(Long id) throws EmployeeNotFoundException {
		// TODO Auto-generated method stub
		 if (id <= 0) {
	            throw new EmployeeNotFoundException("Employee not found with ID: " + id);
	        }
		Employee byId = repository.findById(id).orElseThrow(()->new ResourceNotFoundException("Employee not found with user id "+id));
		
			
		return byId;
	}


	public void deleteEmployee(Long id) {
		repository.deleteById(id);		
	}
	
}
