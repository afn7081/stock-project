package com.stock.tracker.web.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("/hello")
    public  String hello(){
        return "hi";
    }
    @GetMapping("/admin")
    public String admin(){
        return "HI admin here";
    }
}
