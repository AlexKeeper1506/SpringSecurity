package com.example.springsecurity.jwt;

public interface RevocationCheckService {
    public boolean isRevoked(String tokenId);
}
