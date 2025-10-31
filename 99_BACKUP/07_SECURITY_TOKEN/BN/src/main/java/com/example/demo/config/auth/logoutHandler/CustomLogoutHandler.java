package com.example.demo.config.auth.logoutHandler;

import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.config.auth.jwt.JwtProperties;
import com.example.demo.config.auth.jwt.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

@Slf4j
public class CustomLogoutHandler implements org.springframework.security.web.authentication.logout.LogoutHandler {

    @Value("${spring.security.oauth2.client.registration.naver.client-id}")
    private String NAVER_CLIENT_ID;
    @Value("${spring.security.oauth2.client.registration.naver.client-secret}")
    private String NAVER_CLIENT_SECRET;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        log.info("CustomLogoutHandler's logout invoke...");
        HttpSession session = request.getSession(false);
        if(session!=null)
            session.invalidate();

        //JWT TOKEN -> AUTHENTICATION연결
        String token = Arrays.stream(request.getCookies())
                        .filter(cookie -> cookie.getName().equals(JwtProperties.COOKIE_NAME)).findFirst()
                        .map(cookie -> cookie.getValue())
                        .orElse(null);
        if(token!=null){
            authentication = jwtTokenProvider.getAuthentication(token);
        }


        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        String accessToken = principalDetails.getAccessToken();
        String provider = principalDetails.getUserDto().getProvider();

        System.out.println("provider : " + provider);
        if(provider!=null && provider.startsWith("kakao")){
            String url = "https://kapi.kakao.com/v1/user/logout";
            //HTTP 요청 헤더
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization","Bearer "+accessToken);

            //HTTP 엔티티(헤더 + 파라미터)
            HttpEntity entity = new HttpEntity<>(headers);

            //HTTP 요청 후 응답받기
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<String> resp = restTemplate.exchange(url, HttpMethod.POST,entity,String.class);
            System.out.println(resp.getBody());

        }else if(provider!=null && provider.startsWith("naver")){
            //URL
            String url="https://nid.naver.com/oauth2.0/token?grant_type=delete&client_id="+NAVER_CLIENT_ID+"&client_secret="+NAVER_CLIENT_SECRET+"&access_token="+accessToken;
            //HEADER
            HttpHeaders headers = new HttpHeaders();
            //PARAM
            MultiValueMap<String,String> params = new LinkedMultiValueMap<>();

            //ENTITY
            HttpEntity< MultiValueMap<String,String> > entity = new HttpEntity(params,headers);

            //REQUEST
            RestTemplate rt = new RestTemplate();
            ResponseEntity<String> resp = rt.exchange(url, HttpMethod.GET,null,String.class);

            //RESPONSE
            System.out.println(resp.getBody());
        }else if(provider!=null && provider.startsWith("google")){
            //URL
            String url="https://accounts.google.com/o/oauth2/revoke?token="+accessToken;
            //HEADER
            HttpHeaders headers = new HttpHeaders();
            //PARAM
            MultiValueMap<String,String> params = new LinkedMultiValueMap<>();

            //ENTITY
            HttpEntity< MultiValueMap<String,String> > entity = new HttpEntity(params,headers);

            //REQUEST
            RestTemplate rt = new RestTemplate();
            ResponseEntity<String> resp = rt.exchange(url, HttpMethod.GET,null,String.class);

            //RESPONSE
            System.out.println(resp.getBody());
        }

    }
}
