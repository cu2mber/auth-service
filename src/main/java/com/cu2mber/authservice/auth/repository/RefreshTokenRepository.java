package com.cu2mber.authservice.auth.repository;

import com.cu2mber.authservice.auth.domain.RefreshToken;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * RefreshToken 엔티티에 대한 데이터 액세스 처리를 담당하는 레포지토리
 * <p>사용자별 토큰 관리 및 만료된 토큰의 일괄 삭제 기능을 제공합니다.</p>
 */
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    /**
     * 사용자 번호로 토큰 정보 조회
     */
    Optional<RefreshToken> findByMemberNo(Long memberNo);

    /**
     * 토큰 문자열(String)로 토큰 정보 조회
     * <p>사용자가 헤더에 담아 보낸 '문자열'과 DB의 '문자열'을 비교합니다.</p>
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * 특정 일시보다 이전(Before)인 만료 시간을 가진 토큰 일괄 삭제
     * @param now 현재 시간
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken r WHERE r.expiryDate < :now")
    void deleteByExpiryDateBefore(@Param("now")LocalDateTime now);
}
