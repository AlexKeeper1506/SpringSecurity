package com.example.springsecurity;

import com.example.springsecurity.jwt.RevocationCheckService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;

@SpringBootApplication
public class SpringSecurityApplication {
    private static final Logger logger = LoggerFactory.getLogger(SpringSecurityApplication.class);

    public static final DefaultJWTProcessor<SecurityContext> jwtProcessor =
            new DefaultJWTProcessor<>() {
                {
                    try {
                        setJWSKeySelector(
                                new JWSVerificationKeySelector<>(
                                        JWSAlgorithm.RS256,
                                        new ImmutableJWKSet<>(
                                                JWKSet.load(
                                                        SpringSecurityApplication.class.getClassLoader().getResourceAsStream("keyset.json")
                                                )
                                        )
                                )
                        );
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    setJWTClaimsSetVerifier(
                            new DefaultJWTClaimsVerifier<>(
                                    new JWTClaimsSet.Builder().build(),
                                    Set.of(
                                            JWTClaimNames.SUBJECT,
                                            JWTClaimNames.EXPIRATION_TIME,
                                            "scp",
                                            JWTClaimNames.JWT_ID
                                    )
                            )
                    );
                }
            };

    public static class JwtAuthenticationToken implements Authentication {
        private boolean isAuthenticated = true;
        private final String username;
        private final List<SimpleGrantedAuthority> roles;

        public JwtAuthenticationToken(String username, List<SimpleGrantedAuthority> roles) {
            this.username = username;
            this.roles = roles;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return roles;
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Object getDetails() {
            return null;
        }

        @Override
        public Object getPrincipal() {
            return (Principal) () -> username;
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
            return username;
        }

        @Override
        public String toString() {
            return "JwtAuthenticationToken{" +
                    "username='" + username + '\'' +
                    ", roles=" + roles +
                    '}';
        }
    }

    @Autowired
    RevocationCheckService revocationCheckService;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        var contextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

        return http
                .authorizeHttpRequests(c -> c
                        .requestMatchers("/**").authenticated()
                )
                .addFilterBefore(
                        (request, response, filterChain) -> {
                            var token = ((HttpServletRequest) request).getHeader("X-AUTHENTICATION");

                            if (token != null) try {
                                var claimSet = SpringSecurityApplication.jwtProcessor.process(token, null);
                                var tokenId = claimSet.getJWTID();

                                if (revocationCheckService.isRevoked(tokenId))
                                    throw new RuntimeException("token with id " + tokenId + " revoked");

                                var context = contextHolderStrategy.createEmptyContext();
                                var authentication = new JwtAuthenticationToken(
                                        claimSet.getSubject(),
                                        Arrays.stream(((String) claimSet.getClaim("scp")).split(" "))
                                                .map(SimpleGrantedAuthority::new)
                                                .toList()
                                );

                                context.setAuthentication(authentication);
                                contextHolderStrategy.setContext(context);
                            } catch (Exception e) {
                                logger.error(e.getMessage(), e);
                            }

                            filterChain.doFilter(request, response);
                        },
                        AnonymousAuthenticationFilter.class
                )
                .build();
    }

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }
}
