package com.example.demo.config.auth.jwt;

/**
 * JWT 기본 설정값
 */
public class JwtProperties {
    public static final int EXPIRATION_TIME = 1000*60; // 60초
    public static final int EXPIRATION_TIME_REFRESH = 1000*60*3; // 60초
    public static final String COOKIE_NAME = "accesstoken";
}