package com.cu2mber.authservice.auth.util;

import com.cu2mber.authservice.auth.repository.RefreshTokenRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenCleanupScheduler {

    private final RefreshTokenRepository refreshTokenRepository;

    /**
     * 매일 새벽 3시에 만료된 리프레시 토큰을 DB에서 일괄 삭제합니다.
     * cron: "초 분 시 일 월 요일"
     */
    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("만료된 리프레시 토큰 삭제 스케줄러 실행");
        refreshTokenRepository.deleteByExpiryDateBefore(LocalDateTime.now());
        log.info("만료된 토큰 청소 완료");
    }
}