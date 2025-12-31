package com.cu2mber.authservice.auth.util;

import io.jsonwebtoken.Claims;
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
     * JWT를 파싱하여 내부의 Claims(Payload)를 추출합니다.
     * <p>
     * 이 메서드는 단 한 번의 호출로 다음과 같은 작업을 수행합니다.
     * <ul>
     * <li>토큰의 서명(Signature) 위조 여부 검증</li>
     * <li>토큰의 유효 기간 및 만료 여부(Expiration) 자동 확인</li>
     * </ul>
     * 만약 토큰이 만료되었거나 구조가 유효하지 않을 경우, 예외를 발생시키므로
     * 호출 측에서 추가적인 만료 체크 로직을 구현할 필요가 없습니다.
     * </p>
     *
     * @param token 추출할 JWT 문자열
     * @return 추출된 Claims(사용자 정보 및 권한 등)
     * @throws io.jsonwebtoken.ExpiredJwtException 토큰의 유효 기간이 만료된 경우 발생
     * @throws io.jsonwebtoken.JwtException 토큰이 변조되었거나 형식이 잘못된 경우 발생
     */
    public Claims getPayload(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseClaimsJws(token)
                .getPayload();
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
