package com.stock.tracker.web.service.impl;

import com.stock.tracker.entity.User;
import com.stock.tracker.repository.UserRepository;
import com.stock.tracker.web.config.JwtUtil;
import com.stock.tracker.web.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {


    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    @Override
    public void registerUser(User user) {
        // Perform validation and registration logic
        // Save the user details in the database
        userRepository.save(user);
    }

    @Override
    public void authenticateUser(String username, String password) throws Exception{
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username,password));



    }

    @Override
    public User getUserByUserName(String userName) {
        User user= userRepository.findByUsername(userName);
        if (user==null){
            throw new AuthenticationServiceException("User Does not exist");
        }
        return user;
    }

    @Override
    public String getjwtToken(User user) {
        try {
            String jwtToken=jwtUtil.generateToken(user);
            return jwtToken;

        }catch (Throwable t){
          throw  new BadCredentialsException("Can't generate token bad credentials");
        }
    }


}
