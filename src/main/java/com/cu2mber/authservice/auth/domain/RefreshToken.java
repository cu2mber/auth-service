package com.cu2mber.authservice.auth.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * JWT 리프레시 토큰 정보를 관리하는 엔티티 클래스입니다.
 * <p>
 * 사용자의 고유 식별자와 발급된 리프레시 토큰 값을 매핑하여 저장하며,
 * 액세스 토큰 만료 시 재발급을 위한 검증 용도로 사용됩니다.
 * </p>
 *
 */
@Entity
@Table(name="refresh_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {

    /**
     * 리프레시 토큰의 고유 식별자 (Primary Key)
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;

    /**
     * Member Service에서 관리하는 사용자의 고유 번호
     * <p>서비스 간 결합도를 낮추기 위해 연관관계 매핑 대신 ID 값만 직접 저장합니다.</p>
     */
    @Column(nullable = false, unique = true)
    Long memberNo;

    /**
     * 실제 발급된 JWT 리프레시 토큰 문자열
     */
    @Column(nullable = false, length = 500)
    private String token;

    /**
     * 해당 토큰의 만료 일시
     */
    @Column(nullable = false)
    LocalDateTime expiryDate;

    public RefreshToken(Long memberNo, String token, LocalDateTime expiryDate) {
        this.memberNo = memberNo;
        this.token = token;
        this.expiryDate = expiryDate;
    }

    public void updateToken(String newToken, LocalDateTime newExpiryDate) {
        this.token = newToken;
        this.expiryDate = newExpiryDate;
    }
}
