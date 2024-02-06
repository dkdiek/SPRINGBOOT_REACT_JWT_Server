package com.joeun.server.security.jwt.filter;

import com.joeun.server.security.jwt.constants.JwtConstants;
import com.joeun.server.security.jwt.provider.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    //생성자
    public JwtRequestFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /*
    jwt 요청 필터
    -request > 헤더 > authorization (jwt)
    -jwt 토큰 유효성 검사
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //헤더에서 jwt 토큰 가져온다
        String header = request.getHeader(JwtConstants.TOKEN_HEADER);
        log.info("authorization: " + header);

        //jwt 토큰이 없으면 다음 필터로 이동 Authenticationfilter
        if(header == null || header.length() == 0 || !header.startsWith(JwtConstants.TOKEN_PREFIX)){
            filterChain.doFilter(request, response);
            return;
        }

        //jwt토큰해석
        //bearer 제거
        String jwt = header.replace(JwtConstants.TOKEN_PREFIX, "");

        //토큰 해석
        Authentication authentication = jwtTokenProvider.getAuthentication(jwt);

        //토큰 유효성 검사
        if(jwtTokenProvider.validateToken(jwt)){
            //인증 처리
            log.info("유효한 jwt 토큰입니다.");

            //로그인
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        // 다음 필터
        filterChain.doFilter(request,response);


    }
}
