package com.cu2mber.authservice.common.config;

import com.cu2mber.authservice.auth.util.JWTFilter;
import com.cu2mber.authservice.auth.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

/**
 * Spring Security 보안 설정 클래스
 * JWT 기반 무상태(Stateless) 인증 및 CORS 설정을 관리합니다.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JWTUtil jwtUtil;

    /**
     * 보안 필터 체인 정의
     * 허용 주소 설정 및 JWT 필터를 인증 프로세스 앞에 추가합니다.
     * 추후, 로그인 안 해도 접근할 수 있는 경로 추가 예정
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .formLogin(form -> form.disable())
                .httpBasic(httpBasic -> httpBasic.disable())

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/issue", "/auth/refresh", "/auth/logout").permitAll()
                        .requestMatchers( "/api/events/**", "/api/home/**", "/api/notices/**").permitAll()
                        .anyRequest().authenticated())

                // 갱신 요청 등을 보낼 때 이미 가진 토큰이 유효한지 확인하는 필터만 유지
                .addFilterBefore(new JWTFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class)

                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    /**
     * CORS(Cross-Origin Resource Sharing) 설정
     * <p>현재 로컬 개발 환경(http://localhost:3000)에 대해 모든 HTTP 메서드 및 헤더를 허용합니다.</p>
     * <p>배포 환경으로 전환 시 허용 도메인(AllowedOrigins) 수정이 필요합니다.</p>
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        return request -> {
            CorsConfiguration configuration = new CorsConfiguration();
            configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000")); // 허용할 도메인
            configuration.setAllowedMethods(Collections.singletonList("*")); // 모든 HTTP 메서드 허용
            configuration.setAllowCredentials(true); // 인증 정보 포함 허용
            configuration.setAllowedHeaders(Collections.singletonList("*")); // 모든 헤더 허용
            configuration.setExposedHeaders(Collections.singletonList("Authorization")); // Authorization 헤더 노출
            configuration.setMaxAge(1800L); // 30분 동안 캐싱
            return configuration;
        };
    }
}