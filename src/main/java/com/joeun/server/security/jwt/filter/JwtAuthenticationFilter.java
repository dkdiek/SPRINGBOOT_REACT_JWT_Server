package com.joeun.server.security.jwt.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

/*
          (/login)
client -> filter -> server
username,password 인증시도(attemptAuthentication)
인증 실패: response status에 401을 담는다
인증 성공(successfulAuthentication)
-jwt토큰 생성
-response > headers > authorization에 jwt를 담는다
 */
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    // 생성자
    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        //필터 url 경로 설정: /login
        setFilterProcessesUrl("/login");
    }

    /*
        인증 시도 메소드
        /login 경로로 요청하면 필터로 걸러서 인증을 시도
         */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        log.info("username:" + username);
        log.info("password:" + password);

        //사용자 인증정보 객체 생성
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, password);

        //사용자 인증 (로그인)
        authentication = authenticationManager.authenticate(authentication);

        log.info("인증 여부: " + authentication.isAuthenticated());

        //인증실패(username,userpassword 불일치)
        if(!authentication.isAuthenticated()){
            log.info("인증 실패 : 아이디 또는 비밀번호가 일치하지 않습니다.");
            response.setStatus(401);
        }
        
        return authentication;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
    }
}