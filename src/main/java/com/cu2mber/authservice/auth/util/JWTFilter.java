package com.cu2mber.authservice.auth.util;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 모든 요청에서 JWT 액세스 토큰의 유효성을 검증하는 필터입니다.
 */
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1. 헤더에서 Authorization 토큰 추출
        String authorization = request.getHeader("Authorization");

        // 2. 토큰이 없거나 Bearer 형식이 아니면 다음 필터로 이동
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorization.split(" ")[1];

        // 3. 토큰 만료 여부 확인
        try {
            if (jwtUtil.isTokenExpired(token)) {
                filterChain.doFilter(request, response);
                return;
            }
        } catch (Exception e) {
            filterChain.doFilter(request, response);
            return;
        }

        // 4. 토큰에서 정보 추출 (memberNo, role)
        Long memberNo = jwtUtil.getMemberNo(token);
        String role = jwtUtil.getRole(token);

        // 5. 스프링 시큐리티 전용 유저 객체 생성 및 인증 설정
        // 여기서는 간단하게 사용자 번호와 권한만 저장합니다.
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(memberNo, null, null);

        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
