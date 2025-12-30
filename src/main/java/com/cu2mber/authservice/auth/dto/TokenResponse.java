package com.cu2mber.authservice.auth.dto;

/**
 * 토큰 발급 성공 시 반환되는 응답 DTO
 * * @param accessToken  리소스 접근을 위한 액세스 토큰
 * @param refreshToken 액세스 토큰 만료 시 재발급을 위한 리프레시 토큰
 */
public record TokenResponse(String accessToken, String refreshToken) {
}
