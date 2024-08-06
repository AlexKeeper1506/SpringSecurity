package com.example.springsecurity.jwt;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.TimeUnit;

@Component
public class CachingRevocationCheckService implements RevocationCheckService {
    public volatile Set<String> revokeIds = Set.of();

    @Override
    public boolean isRevoked(String tokenId) {
        return revokeIds.contains(tokenId);
    }

    @Scheduled(fixedDelay = 5, timeUnit = TimeUnit.SECONDS)
    void updateRevokedList() {
        revokeIds = Set.of(
                "123"
        );
    }
}
