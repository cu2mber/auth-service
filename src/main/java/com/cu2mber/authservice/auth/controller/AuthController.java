package com.cu2mber.authservice.auth.controller;

import com.cu2mber.authservice.auth.dto.AccessToken;
import com.cu2mber.authservice.auth.dto.IssueRequest;
import com.cu2mber.authservice.auth.dto.TokenResponse;
import com.cu2mber.authservice.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // 1. 최초 토큰 발급 (member-service가 호출함)
    @PostMapping("/issue")
    public ResponseEntity<TokenResponse> issueToken(@RequestBody IssueRequest request) {
        TokenResponse tokens = authService.createTokens(request.getMemberId(), request.getRole());
        return ResponseEntity.ok(tokens);
    }

    // 2. 리프레시 토큰으로 엑세스 토큰 재발급 (사용자가 직접 호출함)
    @PostMapping("/refresh")
    public ResponseEntity<AccessToken> refreshToken(@RequestHeader("Refresh-Token") String refreshToken) {
        AccessToken newAccessToken = authService.refreshAccessToken(refreshToken);
        return ResponseEntity.ok(newAccessToken);
    }
}