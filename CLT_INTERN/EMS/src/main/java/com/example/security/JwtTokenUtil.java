package com.example.security;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtTokenUtil {
	   private static final String SECRET_KEY = "mySecretKey"; // In production, use a secure key
	    private static final long EXPIRATION_TIME = 1000 * 60 * 60; // 1 hour

	    public String generateToken(String username) {
	        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
	        return JWT.create()
	                .withSubject(username)
	                .withIssuedAt(new Date())
	                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
	                .sign(algorithm);
	    }

	    public String extractUsername(String token) {
	        return extractClaims(token).getSubject();
	    }

	    public DecodedJWT extractClaims(String token) {
	        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
	        return JWT.require(algorithm)
	                .build()
	                .verify(token);
	    }

	    public boolean isTokenExpired(String token) {
	        return extractClaims(token).getExpiresAt().before(new Date());
	    }

	    public boolean validateToken(String token, String username) {
	        return (username.equals(extractUsername(token)) && !isTokenExpired(token));
	    }
}
