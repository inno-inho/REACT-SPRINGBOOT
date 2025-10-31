package com.example.demo.config;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DataSourceConfig {

    @Bean
    public HikariDataSource dataSource()
    {
        return 	DataSourceBuilder.create()

                .type(HikariDataSource.class)
                .username("root")
                .password("1234")
                .driverClassName("com.mysql.cj.jdbc.Driver")
                .url("jdbc:mysql://localhost:3306/testdb")
                .build();
    }
}
