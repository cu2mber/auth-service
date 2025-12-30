package com.cu2mber.authservice.auth.util;

import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Jwts;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * JWT 생성 및 검증 유틸리티
 * HS256 알고리즘을 사용하여 토큰의 생명주기를 관리합니다.
 */
@Component
public class JWTUtil {

    private final SecretKey secretKey;

    /**
     * 생성자에서 application.properties에 저장된 SecretKey 값을 가져와 설정
     */
    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    /**
     * JWT에서 사용자 정보(memberNo) 추출
     */
    public Long getMemberNo(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseClaimsJws(token)
                .getPayload()
                .get("memberNo", Long.class);
    }

    /**
     * JWT에서 role(권한) 추출
     */
    public String getRole(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseClaimsJws(token)
                .getPayload()
                .get("role", String.class);
    }

    /**
     * 토큰 유효 기간 및 만료 여부 확인
     */
    public Boolean isTokenExpired(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getPayload()
                    .getExpiration()
                    .before(new Date());
        } catch (ExpiredJwtException e) {
            // 토큰이 만료된 경우
            return true;
        }
    }

    /**
     * 신규 액세스/리프레시 토큰 발급
     * @param category  토큰 종류 (access, refresh)
     * @param memberNo  사용자 고유 번호
     * @param role      사용자 권한
     * @param expiredMs 만료 시간 (밀리초)
     * @return 생성된 JWT 문자열
     */
    public String createToken(String category, Long memberNo, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("category", category)
                .claim("memberNo", memberNo)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }
}
