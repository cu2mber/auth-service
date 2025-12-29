package com.cu2mber.authservice.auth.service.impl;

import com.cu2mber.authservice.auth.dto.AccessToken;
import com.cu2mber.authservice.auth.dto.TokenResponse;
import com.cu2mber.authservice.auth.service.AuthService;

public class AuthServiceImpl implements AuthService {
    @Override
    public TokenResponse createTokens(Long memberId, String role) {
        return null;
    }

    @Override
    public AccessToken refreshAccessToken(String refreshToken) {
        return null;
    }
}
