package com.stock.tracker.web.object;

import lombok.Data;

@Data
public class AuthenticationRequest {

    private String userName;
    private String password;
}
