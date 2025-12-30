package com.cu2mber.authservice.auth.util;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * HTTP 요청 당 1회 실행되는 JWT 인증 필터
 * 헤더의 Authorization 토큰을 검증하고 SecurityContext에 인증 정보를 등록합니다.
 */
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    /**
     * 토큰 검증 로직 수행
     * 만료된 토큰의 경우 401 에러와 메시지를 반환합니다.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 헤더에서 Authorization 토큰 추출
        String authorization = request.getHeader("Authorization");

        // 토큰이 없거나 Bearer 형식이 아니면 다음 필터로 이동
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorization.split(" ")[1];

        // 토큰 만료 여부 확인
        try {
            if (jwtUtil.isTokenExpired(token)) {
                setResponse(response, "AccessToken has expired", HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        } catch (Exception e) {
            setResponse(response, "Invalid Token", HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        Long memberNo = jwtUtil.getMemberNo(token);
        String role = jwtUtil.getRole(token);

        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(memberNo, null, List.of(new SimpleGrantedAuthority(role)));

        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }

    private void setResponse(HttpServletResponse response, String message, int status) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(status);
        response.getWriter().println("{\"message\" : \"" + message + "\"}");
    }
}
