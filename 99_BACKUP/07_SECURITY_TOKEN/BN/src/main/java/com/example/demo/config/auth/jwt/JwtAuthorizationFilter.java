package com.example.demo.config.auth.jwt;


import com.example.demo.domain.entity.JWTToken;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.JWTTokenRepository;
import com.example.demo.domain.repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.thymeleaf.util.StringUtils;


import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

/**
 * JWT를 이용한 인증
 */
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final UserRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final JWTTokenRepository jwtTokenRepository;

    public JwtAuthorizationFilter(
            UserRepository memberRepository,
            JwtTokenProvider jwtTokenProvider,
            JWTTokenRepository jwtTokenRepository
    ) {
        this.memberRepository = memberRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtTokenRepository = jwtTokenRepository;

    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws IOException, ServletException, IOException {
        System.out.println("[JWTAUTHORIZATIONFILTER] doFilterInternal...");
        String token = null;
        try {
            //token == null - header값 확인코드 추가
            String authorizationHeader = request.getHeader("Authorization");
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer "))
                token = authorizationHeader.substring(7);

            System.out.println("JWTAUTHORIZATIONFILTER] doFilterInternal...  async token : " + token );

            if (token != null) {
                    //DB 토큰 받기
                    JWTToken previousToken = jwtTokenRepository.findByAccessToken(token);//username 가져오기
                    if(jwtTokenProvider.validateTokenAsync(token)) {

                        JWTToken dbToken= jwtTokenRepository.findByUsername(previousToken.getUsername());
                        //CLIENT로부터 받은 토큰 vs DB 토큰
                        if(StringUtils.equals(dbToken.getAccessToken(),token)){
                            //access-token 유효함(갱신x)
                            Authentication authentication = getUsernamePasswordAuthenticationToken(token);
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                            System.out.println("[DOFILTER] Access Token 유효함");
                        }else{
                            //access-token 갱신됨(client token X -> DB token 으로대체)
                            Authentication authentication = getUsernamePasswordAuthenticationToken(dbToken.getAccessToken());
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                            System.out.println("[DOFILTER] Access Token 갱신됨(Refresh token 유효함)");
                        }
                    }else{
                        System.out.println("[DOFILTER] refresh Token 만료됨");
//                        Authentication authentication = new UsernamePasswordAuthenticationToken(null , null);
//                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
            }else {
                System.out.println("[DOFILTER] Token null..");
//                Authentication authentication = new UsernamePasswordAuthenticationToken(null , null);
//                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        catch(Exception e2) {

        }
        chain.doFilter(request, response);
    }

    /**
     * JWT 토큰으로 User를 찾아서 UsernamePasswordAuthenticationToken를 만들어서 반환한다.
     * User가 없다면 null
     */
    private Authentication getUsernamePasswordAuthenticationToken(String token) {

        Authentication authentication = jwtTokenProvider.getAuthentication(token);
        Optional<User> user = memberRepository.findById(authentication.getName()); // 유저를 유저명으로 찾습니다.
        //System.out.println("JwtAuthorizationFilter.getUsernamePasswordAuthenticationToken...authenticationToken : " +authentication );
        if(user!=null)
        {
            return authentication;
        }
        return null; // 유저가 없으면 NULL
    }

}