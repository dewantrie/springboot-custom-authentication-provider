package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
    private static final String AUTH_LOGIN_VIEW = "auth/login";

    @GetMapping("/login")
    public String showLoginForm(Model model) {
        return AUTH_LOGIN_VIEW;
    }

}
