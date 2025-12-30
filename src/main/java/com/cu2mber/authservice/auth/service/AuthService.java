package com.cu2mber.authservice.auth.service;

import com.cu2mber.authservice.auth.dto.AccessToken;
import com.cu2mber.authservice.auth.dto.TokenResponse;

public interface AuthService {
    TokenResponse createTokens(Long memberNo, String role);

    AccessToken refreshAccessToken(String refreshToken);

    void logout(String refreshToken);
}
