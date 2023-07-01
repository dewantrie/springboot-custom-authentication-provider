package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class HomeController {
    private static final String HOME_VIEW = "home/index";

    @GetMapping("/home")
    public String home(HttpServletRequest request){
        return HOME_VIEW;
    }
}
