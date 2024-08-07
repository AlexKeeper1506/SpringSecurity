package com.example.springsecurity.oath2;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.Principal;
import java.util.Collection;
import java.util.List;

public class ManualImplementation {
    public static final String OAUTH_REDIRECT_PATH = "/oauth/authorize";
    public static final String OAUTH_REDIRECT_URL = "http://localhost:8080" + OAUTH_REDIRECT_PATH;
    public static final String VK_OAUTH_CLIENT_ID = "51466120";
    public static final String VK_OAUTH_CLIENT_SECRET = "f4E9B4OHxfypUK0N7VZL";
    public static final String OAUTH_SESSION_STATE_ATTRIB = "OAUTH2_STATE";

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class VkTokenResponse {
        public Long userId;
        public String email;
        public String accessToken;
        public Long expiresIn;
    }

    public static class VkAuthenticationToken implements Authentication {
        private boolean isAuthenticated = true;
        private final String email;
        private final long vkId;

        @Override
        public String toString() {
            return "VkAuthenticationToken{" +
                    "email=" + email + "\"" +
                    ", vkId=" + vkId + "}";
        }

        record Details(String email, long vkId) {}

        public VkAuthenticationToken(String email, long vkId) {
            this.email = email;
            this.vkId = vkId;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return List.of(new SimpleGrantedAuthority("ROLE_USER"));
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Object getDetails() {
            return new Details(email, vkId);
        }

        @Override
        public Object getPrincipal() {
            return (Principal) () -> email;
        }

        @Override
        public boolean isAuthenticated() {
            return isAuthenticated;
        }

        @Override
        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
            this.isAuthenticated = isAuthenticated;
        }

        @Override
        public String getName() {
            return email;
        }
    }
}
