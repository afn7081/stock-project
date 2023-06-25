package com.stock.tracker.web.controller;

import com.stock.tracker.entity.User;
import com.stock.tracker.web.service.UserService;
import com.stock.tracker.web.object.AuthenticationRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.*;

import javax.naming.AuthenticationException;
import java.util.Collection;
import java.util.Collections;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController  {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody AuthenticationRequest authenticationRequest){
        // Perform validation and registration logic
        // Save the user details in the database
        log.info("In register");
        try {
            User user=new User();
            user.setUsername(authenticationRequest.getUserName());
            user.setPassword(authenticationRequest.getPassword());
            user.setAuthorities("ROLE_ADMIN");
            userService.registerUser(user);
        }catch (Throwable t){
            log.error("ERROR:{}",t.getMessage());
            return ResponseEntity.ofNullable(t.getMessage());
        }
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<String> loginUser(@RequestBody AuthenticationRequest authenticationRequest) {
        // Authenticate the user
        log.info("In login");

        try {
            return ResponseEntity.ok(userService.authenticateUser(authenticationRequest.getUserName(), authenticationRequest.getPassword()));
        } catch (AuthenticationException ae) {
            log.error("Authentication Error");
            return ResponseEntity.status(401).body(ae.getMessage());
        }catch (BadCredentialsException bce){
            log.info("ERROR:{}",bce.getMessage());
            return ResponseEntity.status(400).body(bce.getMessage());

        }
        catch (Throwable t) {
            log.info("ERROR:{}",t.getMessage());
            return ResponseEntity.status(500).body("Something went wrong");
        }

    }



}
