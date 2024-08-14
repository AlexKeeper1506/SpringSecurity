package com.example.springsecurity.jwt;

public interface RevocationCheckService {
    boolean isRevoked(String tokenId);
}
