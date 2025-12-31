package com.cu2mber.authservice.auth.service;

import com.cu2mber.authservice.auth.dto.AccessToken;
import com.cu2mber.authservice.auth.dto.TokenResponse;

/**
 * 인증 및 토큰 관리 비즈니스 로직을 정의하는 서비스 인터페이스입니다.
 * <p>Access Token과 Refresh Token의 발급, 갱신 및 로그아웃 처리를 담당합니다.</p>
 */
public interface AuthService {

    /**
     * 신규 토큰 세트(Access, Refresh)를 발급하고 Refresh Token을 저장합니다.
     *
     * @param memberNo 사용자 고유 번호
     * @param role     사용자 권한
     * @return 생성된 Access Token과 Refresh Token 정보를 담은 DTO
     */
    TokenResponse createTokens(Long memberNo, String role);

    /**
     * 전달받은 Refresh Token의 유효성을 검증하여 새로운 Access Token을 발급합니다.
     *
     * @param refreshToken 클라이언트로부터 전달받은 리프레시 토큰
     * @return 갱신된 Access Token 정보를 담은 DTO
     * @throws RuntimeException 토큰이 존재하지 않거나 만료/위조된 경우 발생
     */
    AccessToken refreshAccessToken(String refreshToken);

    /**
     * 로그아웃 요청 시 저장된 Refresh Token을 삭제합니다.
     *
     * @param refreshToken 무효화할 리프레시 토큰 문자열
     */
    void logout(String refreshToken);
}
