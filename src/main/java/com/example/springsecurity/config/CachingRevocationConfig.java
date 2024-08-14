package com.example.springsecurity.config;

import com.example.springsecurity.jwt.CachingRevocationCheckService;
import com.example.springsecurity.jwt.RevocationCheckService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@Configuration
public class CachingRevocationConfig {
    @Bean
    RevocationCheckService revocationCheckService() {
        return new CachingRevocationCheckService();
    }
}
