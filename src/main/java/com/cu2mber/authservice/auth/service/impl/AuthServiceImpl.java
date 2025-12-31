package com.cu2mber.authservice.auth.service.impl;

import com.cu2mber.authservice.auth.domain.RefreshToken;
import com.cu2mber.authservice.auth.dto.AccessToken;
import com.cu2mber.authservice.auth.dto.TokenResponse;
import com.cu2mber.authservice.auth.repository.RefreshTokenRepository;
import com.cu2mber.authservice.auth.service.AuthService;
import com.cu2mber.authservice.auth.util.JWTUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/**
 * AuthService 인터페이스의 구현체
 * <p>JWTUtil을 통한 토큰 생성 및 검증, RefreshTokenRepository를 통한 DB 관리를 수행합니다.</p>
 */
@Service
@RequiredArgsConstructor
@Transactional
public class AuthServiceImpl implements AuthService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JWTUtil jwtUtil;

    /**
     * {@inheritDoc}
     * <p>JWTUtil을 사용해 토큰을 생성하며, 생성된 Refresh Token은 DB(Amazon RDS)에 저장합니다.</p>
     */
    @Override
    public TokenResponse createTokens(Long memberNo, String role) {
        // JWTUtil을 사용하여 토큰 생성
        String accessToken = jwtUtil.createToken("access", memberNo, role, 1800000L); // 30분
        String refreshToken = jwtUtil.createToken("refresh", memberNo, role, 1209600000L); // 14일

        // 생성된 Refresh Token을 RDS에 저장
        saveRefreshToken(memberNo, refreshToken);

        return new TokenResponse(accessToken, refreshToken);
    }

    /**
     * {@inheritDoc}
     * <p>전달받은 리프레시 토큰의 유효성(DB 대조 및 JWT 만료/변조)을 검증하고,
     * 검증 성공 시 새로운 액세스 토큰을 생성하여 반환합니다.</p>
     */
    @Override
    public AccessToken refreshAccessToken(String refreshToken) {
        // DB에 해당 토큰이 존재하는지 확인
        RefreshToken storedToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("존재하지 않는 리프레시 토큰입니다."));

        // JWT 자체 만료 확인
        try {
            Claims claims = jwtUtil.getPayload(refreshToken);

            String userRole = claims.get("role", String.class);

            String newAccessToken = jwtUtil.createToken("access", storedToken.getMemberNo(), userRole, 1800000L);

            return new AccessToken(newAccessToken);

        } catch (ExpiredJwtException e) {
            throw new RuntimeException("리프레시 토큰이 만료되었습니다. 다시 로그인해주세요.");
        } catch (Exception e) {
            throw new RuntimeException("유효하지 않은 토큰입니다.");
        }
    }

    /**
     * {@inheritDoc}
     * <p>DB에서 해당 토큰 존재 여부를 확인한 후 삭제 처리를 진행합니다.</p>
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
