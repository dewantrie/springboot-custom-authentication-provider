package com.example.demo.domain.model;

import lombok.Data;

@Data
public class TokenModel {
    private String accessToken;
    private String refreshToken;
}
