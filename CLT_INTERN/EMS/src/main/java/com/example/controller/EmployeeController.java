package com.example.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.entity.Employee;
import com.example.exception.EmployeeNotFoundException;
import com.example.exception.ResourceNotFoundException;
import com.example.service.EmployeeService;

@RestController
public class EmployeeController {

	@Autowired
	private EmployeeService service;
	
	@PostMapping("/create")
	public ResponseEntity<?> createEmployee(@RequestBody Employee emp){
		Employee employee=service.createEmployee(emp);
		return new ResponseEntity<>(employee, HttpStatus.CREATED);
	}
	
	
	//RESPONSE_ENTITY
	@GetMapping("/get/{id}")
	public ResponseEntity<?> getEmployee(@PathVariable Long id){
		try {
            Employee employee = service.getEmployee(id);
            return ResponseEntity.ok(employee);
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Resource not found");
        } catch (EmployeeNotFoundException e) {
			// TODO Auto-generated catch block
        	 return ResponseEntity.status(HttpStatus.NOT_FOUND).body("employee not found");
			
		}
	}
	//VOID_TYPE
	 @DeleteMapping("/delete/{id}")
	    public void deleteEmployee(@PathVariable Long id) {
	        service.deleteEmployee(id);
	    }
	 
	 @GetMapping("/returnStringData")
	 public String Welcome() {
		 return "Hello!Welcome to EMS!!!!";
	 }
	 
	 //modelmap_type
	 @GetMapping("/employee/{id}")
	 public ModelMap getEmployeeDetails(@PathVariable Long id) {
	     ModelMap model = new ModelMap();
	     try {
	         Employee employee = service.getEmployee(id);
	         model.addAttribute("id", employee.getId());
	         model.addAttribute("name", employee.getName());
	         model.addAttribute("type", employee.getType());
	         model.addAttribute("branch", employee.getBranch());
	         model.addAttribute("salary", employee.getSalary());
	     } catch (ResourceNotFoundException e) {
	         model.addAttribute("error", "Resource not found");
	     } catch (EmployeeNotFoundException e) {
	         model.addAttribute("error", "Employee not found");
	     }
	     return model;
	 }

	 
	 
	
}
