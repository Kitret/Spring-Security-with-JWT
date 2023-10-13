package com.kitret.springsecurityjwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kitret.springsecurityjwt.models.AuthenticationRequest;
import com.kitret.springsecurityjwt.models.AuthenticationResponse;
import com.kitret.springsecurityjwt.service.MyUserDetailsService;
import com.kitret.springsecurityjwt.utils.JWTutils;

import org.springframework.web.bind.annotation.RequestBody;


@RestController
public class HelloResources {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private JWTutils jwtTokenUtils;

    @GetMapping("/")
    public String home(){
        return "Welcome Home";
    }
    
    @GetMapping("/hello")
    public String hello(){
        return "Hello world";
    }

    @PostMapping(value="/authenticate")
    public ResponseEntity<?> createAuthenticationTokEntity(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(), authenticationRequest.getPassword())
            );
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect User name and Password", e);
        }

        final UserDetails UserDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUserName());

        final String jwt = jwtTokenUtils.generateToken(UserDetails);

        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }

}
