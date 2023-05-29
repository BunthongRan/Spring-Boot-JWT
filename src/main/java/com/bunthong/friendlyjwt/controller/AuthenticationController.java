package com.bunthong.friendlyjwt.controller;

import com.bunthong.friendlyjwt.service.TokenService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {
   private final TokenService tokenService;
    AuthenticationController(TokenService tokenService){
        this.tokenService = tokenService;
    }

    @GetMapping ("/token")
    public String getToken(Authentication authentication){
        String token = tokenService.generateToken(authentication);
                return token;
    }
}
