package com.stock.tracker.web.service;

import com.stock.tracker.entity.User;
import org.springframework.security.core.userdetails.UserDetails;

public interface UserService {

    void registerUser(User user);

    String authenticateUser(String username, String password) throws Exception;



}
