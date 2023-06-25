package com.stock.tracker.web.controller;

import com.stock.tracker.entity.User;
import com.stock.tracker.web.service.UserService;
import com.stock.tracker.web.object.AuthenticationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.naming.AuthenticationException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AuthControllerTest {

    @Mock
    private UserService userService;

    private MockMvc mockMvc;
    @InjectMocks
    private AuthController authController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        mockMvc = MockMvcBuilders.standaloneSetup(authController).build();
    }

    @Test
    void testRegisterUser_Success() throws Exception {
        AuthenticationRequest request = new AuthenticationRequest();
        request.setUserName("john_doe");
        request.setPassword("password");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ \"userName\": \"john_doe\", \"password\": \"password\" }"))
                .andExpect(status().isOk())
                .andExpect(content().string("User registered successfully"));

        User expectedUser = new User();
        expectedUser.setUsername("john_doe");
        expectedUser.setPassword("password");
        expectedUser.setAuthorities("ROLE_ADMIN");
        verify(userService, times(1)).registerUser(expectedUser);
    }

    @Test
    void testRegisterUser_Failure() throws Exception {
        AuthenticationRequest request = new AuthenticationRequest();
        request.setUserName("john_doe");
        request.setPassword("password");

        doThrow(new RuntimeException("Registration failed")).when(userService).registerUser(any(User.class));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ \"userName\": \"john_doe\", \"password\": \"password\" }"))
                .andExpect(status().isOk())
                .andExpect(content().string("Registration failed"));
    }

    @Test
    void testLoginUser_Success() throws Exception {
        AuthenticationRequest request = new AuthenticationRequest();
        request.setUserName("john_doe");
        request.setPassword("password");
        User user=new User();
        user.setPassword(request.getPassword());
        user.setUsername(request.getUserName());

        doNothing().when(userService).authenticateUser("john_doe", "password");
        when(userService.getUserByUserName(request.getUserName())).thenReturn(user);
        when(userService.getjwtToken(user)).thenReturn("Login successful");
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ \"userName\": \"john_doe\", \"password\": \"password\" }"))
                .andExpect(status().isOk())
                .andExpect(content().string("Login successful"));
    }

    @Test
    void testLoginUser_BadCredentials() throws Exception {
        AuthenticationRequest request = new AuthenticationRequest();
        request.setUserName("john_doe");
        request.setPassword("password");

        doThrow(new BadCredentialsException("Invalid credentials")).when(userService).authenticateUser("john_doe", "password");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ \"userName\": \"john_doe\", \"password\": \"password\" }"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Invalid credentials"));
    }
    @Test
    void testLoginUser_AuthenticationException() throws Exception {
        AuthenticationRequest request = new AuthenticationRequest();
        request.setUserName("john_doe");
        request.setPassword("password");

        doThrow(new AuthenticationServiceException("Could not authenticate")).when(userService).authenticateUser("john_doe", "password");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ \"userName\": \"john_doe\", \"password\": \"password\" }"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Could not authenticate"));
    }
    @Test
    void testLoginUser_Failure() throws Exception {
        AuthenticationRequest request = new AuthenticationRequest();
        request.setUserName("john_doe");
        request.setPassword("password");

        doThrow(new RuntimeException("Login failed")).when(userService).authenticateUser("john_doe", "password");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ \"userName\": \"john_doe\", \"password\": \"password\" }"))
                .andExpect(status().isInternalServerError())
                .andExpect(content().string("Something went wrong"));
    }
}
