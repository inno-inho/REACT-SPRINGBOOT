package com.example.demo.controller;

import com.example.demo.config.auth.jwt.JwtProperties;
import com.example.demo.config.auth.jwt.JwtTokenProvider;
import com.example.demo.config.auth.jwt.TokenInfo;
import com.example.demo.domain.dto.UserDto;
import com.example.demo.domain.entity.JWTToken;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.JWTTokenRepository;
import com.example.demo.domain.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.util.StringUtils;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
public class UserRestController {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTTokenRepository jwtTokenRepository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @PostMapping(value = "/join",produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<String> join_post(@RequestBody UserDto userDto){
        log.info("POST /join..."+userDto);

        //dto->entity
        User user = User.builder()
                .username(userDto.getUsername())
                .password( passwordEncoder.encode(userDto.getPassword())  )
                .role("ROLE_USER")
                .build();

        // save entity to DB
        userRepository.save(user);

        //
        return new ResponseEntity<String>("success", HttpStatus.OK);
    }



    //
    @PostMapping(value = "/login" , consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity< Map<String,Object> > login(@RequestBody UserDto userDto) throws IOException {
        log.info("POST /login..." + userDto);
        Map<String, Object> response = new HashMap<>();

        //1 접속중인 동일 계정이 있는지 확인
        JWTToken token = jwtTokenRepository.findByUsername(userDto.getUsername());
        if(token!=null){
            //1-1 access-token 만료여부
            //1-2 refresh-token 만료여부
            if(jwtTokenProvider.validateTokenAsync(token.getAccessToken())) {
                //access-token 을 client 전달
                JWTToken reToken =  jwtTokenRepository.findById(token.getId()).get();
                response.put(JwtProperties.COOKIE_NAME, reToken.getAccessToken());
                response.put("state", "success");
                response.put("message", "기존 로그인 정보가 존재합니다.");
                return  new ResponseEntity(response,HttpStatus.OK);
            }else{
                // access-token 만료 && refresh-token  만료
                jwtTokenRepository.deleteById(token.getId());
//                response.put("state", "fail");
//                response.put("message", "access-token만료, 새로 로그인 요청하세요");
//                return response;
            }
        }

        //토큰이 null(DB x)
        try{

            //사용자 인증 시도(ID/PW 일치여부 확인)
            Authentication authentication =
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userDto.getUsername(),userDto.getPassword())
            );
            System.out.println("인증성공 : " + authentication);

            //Token 생성
            TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);
            System.out.println("JWT TOKEN : " + tokenInfo);

            //Token DB저장  -> Redis Server 로 대체가능
            JWTToken tokenEntity = new JWTToken();
            tokenEntity.setAccessToken(tokenInfo.getAccessToken());
            tokenEntity.setRefreshToken(tokenInfo.getRefreshToken());
            tokenEntity.setUsername(userDto.getUsername());
            tokenEntity.setIssuedAt(LocalDateTime.now());
            jwtTokenRepository.save(tokenEntity);
            //
            response.put("state","success");
            response.put("message","인증성공!");
            response.put(JwtProperties.COOKIE_NAME,tokenEntity.getAccessToken());

        }catch(AuthenticationException e){
            System.out.println("인증실패 : " + e.getMessage());
            response.put("state","fail");
            response.put("message",e.getMessage());
            return new ResponseEntity(response,HttpStatus.UNAUTHORIZED);
        }


        return new ResponseEntity(response,HttpStatus.OK);
    }

	@GetMapping("/user")
	public ResponseEntity< Map<String,Object> > user(HttpServletRequest request, Authentication authentication) {
		log.info("GET /user..." + authentication);
        log.info("name..." + authentication.getName());

        Map<String, Object> response = new HashMap<>();

        String token = null;
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer "))
            token = authorizationHeader.substring(7);

        if(token==null){
            ; //token null -> login Page redirect
            response.put("redirect" ,"/login");
            response.put("auth", false);
            return new ResponseEntity<>(response,HttpStatus.UNAUTHORIZED);
        }else{

            if(authentication.getName() == null){
                //accesstoken x refresh x -> DB삭제 x -> login Page redirect
                response.put("redirect" ,"/login");
                response.put("auth", false);
                return new ResponseEntity<>(response,HttpStatus.UNAUTHORIZED);
            }else{

                JWTToken dbToken =  jwtTokenRepository.findByUsername(authentication.getName());

                if(StringUtils.equals(dbToken.getAccessToken(),token)){
                    //accesstoken 유효 refresh 유효 -> User Info 전달
                    response.put("username", authentication.getName());
                    response.put("auth", authentication.isAuthenticated());
                    return new ResponseEntity(response , HttpStatus.OK);
                }else{
                    //accesstoken 갱신(유효) refresh 유효 -> User Info 전달 + 갱신된 accesstoken 전달
                    response.put("username", authentication.getName());
                    response.put("auth", authentication.isAuthenticated());
                    response.put(JwtProperties.COOKIE_NAME,dbToken.getAccessToken());
                    return new ResponseEntity(response , HttpStatus.OK);
                }
            }
        }

	}
}
