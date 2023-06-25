package com.stock.tracker.web.service;

import com.stock.tracker.entity.User;
import org.springframework.security.core.userdetails.UserDetails;

public interface UserService {

    void registerUser(User user);

    void authenticateUser(String username, String password) throws Exception;

    User getUserByUserName(String userName);

    String getjwtToken(User user);

}
