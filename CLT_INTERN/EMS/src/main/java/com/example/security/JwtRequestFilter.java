package com.example.security;


import java.io.IOException;
import java.util.ArrayList;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;

    public JwtRequestFilter(JwtTokenUtil jwtTokenUtil) {
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwtToken = request.getHeader("Authorization");

        if (jwtToken != null && jwtToken.startsWith("Bearer ")) {
            // Extract the token from the Authorization header
            String token = jwtToken.substring(7);
            String username = jwtTokenUtil.extractUsername(token);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // Validate token and set authentication if valid
                if (jwtTokenUtil.validateToken(token, username)) {
                    SecurityContextHolder.getContext().setAuthentication(new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(username, null, new ArrayList<>()));
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
