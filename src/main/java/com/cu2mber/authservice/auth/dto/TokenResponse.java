package com.cu2mber.authservice.auth.dto;

public record TokenResponse(String accessToken, String refreshToken) {
}
