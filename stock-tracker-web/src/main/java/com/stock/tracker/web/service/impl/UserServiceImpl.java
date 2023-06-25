package com.stock.tracker.web.service.impl;

import com.stock.tracker.entity.User;
import com.stock.tracker.repository.UserRepository;
import com.stock.tracker.web.config.JwtUtil;
import com.stock.tracker.web.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {


    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    @Override
    public void registerUser(User user) {
        // Perform validation and registration logic
        // Save the user details in the database
        userRepository.save(user);
    }

    @Override
    public String authenticateUser(String username, String password) throws Exception{

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username,password));
        final UserDetails user=userDetailsService.loadUserByUsername(username);
        if (user!=null){
            return jwtUtil.generateToken(user);
        }
        else {
            throw new AuthenticationServiceException("User Does not exist");
        }
    }

}
