package com.cu2mber.authservice.auth.dto;

/**
 * 토큰 발급 요청을 위한 DTO
 * * @param memberNo 사용자 고유 번호
 * @param role     사용자에게 부여될 권한 (예: ROLE_USER)
 */
public record IssueRequest(Long memberNo, String role) {
}
