package com.cu2mber.authservice.auth.dto;

/**
 * 액세스 토큰 재발급 시 반환되는 응답 DTO
 * * @param accessToken 새롭게 생성된 액세스 토큰
 */
public record AccessToken(String accessToken) {
}
