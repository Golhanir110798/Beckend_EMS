package com.example.security;




import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.entity.Employee;
import com.example.repository.EmployeeRepository;

@RestController
@CrossOrigin(origins  = "http://localhost:3000")
public class AuthenticationController {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private EmployeeRepository employeeRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest authenticationRequest) {
        Employee employee = employeeRepository.findByName(authenticationRequest.getUsername())
            .orElse(null);
            
        if (employee != null && passwordEncoder.matches(authenticationRequest.getPassword(), employee.getPassword())) {
            String token = jwtTokenUtil.generateToken(authenticationRequest.getUsername());
            Map<String, Object> response = new HashMap<>();
            response.put("token", token);
            return ResponseEntity.ok(response);
        }
        
        return ResponseEntity.badRequest().body("Invalid credentials");
    }
}
//@PostMapping("/authenticate")
//public String authenticate(@RequestBody AuthenticationRequest authenticationRequest) {
//    
//    return jwtTokenUtil.generateToken(authenticationRequest.getUsername());
//}