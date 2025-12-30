package com.cu2mber.authservice.auth.service.impl;

import com.cu2mber.authservice.auth.domain.RefreshToken;
import com.cu2mber.authservice.auth.dto.AccessToken;
import com.cu2mber.authservice.auth.dto.TokenResponse;
import com.cu2mber.authservice.auth.repository.RefreshTokenRepository;
import com.cu2mber.authservice.auth.service.AuthService;
import com.cu2mber.authservice.auth.util.JWTUtil;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthServiceImpl implements AuthService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JWTUtil jwtUtil;

    /**
     * 최초 로그인 시 Access Token과 Refresh Token을 생성하고, Refresh Token을 DB에 저장합니다.
     *
     * @param memberNo 사용자 고유 번호
     * @param role     사용자 권한
     * @return 생성된 토큰 세트 (Access, Refresh)
     */
    @Override
    public TokenResponse createTokens(Long memberNo, String role) {
        // JWTUtil을 사용하여 토큰 생성
        String accessToken = jwtUtil.createJwt("access", memberNo, role, 1800000L); // 30분
        String refreshToken = jwtUtil.createJwt("refresh", memberNo, role, 1209600000L); // 14일

        // 생성된 Refresh Token을 RDS에 저장
        saveRefreshToken(memberNo, refreshToken);

        return new TokenResponse(accessToken, refreshToken);
    }

    /**
     * 리프레시 토큰의 유효성을 검증하고 새로운 액세스 토큰을 발급합니다.
     *
     * @param refreshToken 사용자가 전달한 리프레시 토큰
     * @return 새로운 액세스 토큰
     */
    @Override
    public AccessToken refreshAccessToken(String refreshToken) {
        // DB에 해당 토큰이 존재하는지 확인
        RefreshToken storedToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("존재하지 않는 리프레시 토큰입니다."));

        // JWT 자체 만료 확인
        try {
            if (jwtUtil.isTokenExpired(refreshToken)) {
                throw new RuntimeException("리프레시 토큰이 만료되었습니다. 다시 로그인해주세요.");
            }
        } catch (Exception e) {
            // 토큰 파싱 중 에러(위조 등)가 나도 예외 처리
            throw new RuntimeException("유효하지 않은 토큰입니다.");
        }

        String userRole = jwtUtil.getRole(refreshToken);

        // 유효하다면 새로운 Access Token 발급
        String newAccessToken = jwtUtil.createJwt("access", storedToken.getMemberNo(), userRole, 1800000L);

        return new AccessToken(newAccessToken);
    }

    /**
     * 사용자의 리프레시 토큰을 삭제하여 로그아웃 처리를 수행합니다.
     * <p>DB에서 토큰이 삭제되면 더 이상 액세스 토큰 갱신이 불가능해집니다.</p>
     *
     * @param refreshToken 삭제할 리프레시 토큰 문자열
     */
    @Override
    public void logout(String refreshToken) {
        RefreshToken storedToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("이미 로그아웃되었거나 존재하지 않는 토큰입니다."));

        refreshTokenRepository.delete(storedToken);
    }

    /**
     * 발급된 리프레시 토큰을 Amazon RDS에 저장합니다.
     * <p>이미 해당 사용자의 토큰이 존재할 경우 새로운 토큰으로 업데이트합니다.</p>
     *
     * @param memberNo 사용자 고유 번호
     * @param token    발급된 리프레시 토큰 문자열
     */
    private void saveRefreshToken(Long memberNo, String token) {
        // 기존 토큰이 있다면 업데이트, 없으면 새로 생성
        RefreshToken refreshToken = refreshTokenRepository.findByMemberNo(memberNo)
                .map(existingToken -> {
                    existingToken.updateToken(token, LocalDateTime.now().plusDays(14));
                    return existingToken;
                })
                .orElse(new RefreshToken(memberNo, token, LocalDateTime.now().plusDays(14)));

        refreshTokenRepository.save(refreshToken);
    }
}
