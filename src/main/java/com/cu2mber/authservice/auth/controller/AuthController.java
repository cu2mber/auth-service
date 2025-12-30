package com.cu2mber.authservice.auth.controller;

import com.cu2mber.authservice.auth.dto.AccessToken;
import com.cu2mber.authservice.auth.dto.IssueRequest;
import com.cu2mber.authservice.auth.dto.TokenResponse;
import com.cu2mber.authservice.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * 인증 및 토큰 관리 API
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * 최초 토큰 발급 (로그인 시 사용)
     * @param request 사용자 번호 및 권한 정보
     * @return Access & Refresh Token
     */
    @PostMapping("/issue")
    public ResponseEntity<TokenResponse> issueToken(@RequestBody IssueRequest request) {
        TokenResponse tokens = authService.createTokens(request.memberNo(), request.role());
        return ResponseEntity.ok(tokens);
    }

    /**
     * 액세스 토큰 재발급
     * @param refreshToken 헤더의 리프레시 토큰
     * @return 새로운 Access Token
     */
    @PostMapping("/refresh")
    public ResponseEntity<AccessToken> refreshToken(@RequestHeader("Refresh-Token") String refreshToken) {
        AccessToken newAccessToken = authService.refreshAccessToken(refreshToken);
        return ResponseEntity.ok(newAccessToken);
    }

    /**
     * 로그아웃 API
     * @param refreshToken 헤더로 전달받은 리프레시 토큰
     * @return 성공 메시지
     */
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Refresh-Token") String refreshToken) {
        authService.logout(refreshToken);
        return ResponseEntity.ok("로그아웃이 성공적으로 처리되었습니다.");
    }
}