package com.example.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

import static com.example.springsecurity.oath2.ManualImplementation.*;

@Configuration
public class SpringImplConfiguration {
    @Bean
    public SecurityFilterChain filterChainBuiltin(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(c -> c
                        .requestMatchers("/**").authenticated()
                )
                .oauth2Login(c -> {
                    c.clientRegistrationRepository(
                            new InMemoryClientRegistrationRepository(
                                    ClientRegistration.withRegistrationId("vk")
                                            .clientId(VK_OAUTH_CLIENT_ID)
                                            .clientSecret(VK_OAUTH_CLIENT_SECRET)
                                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                                            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                                            .scope("email")
                                            .authorizationUri("https://oauth.vk.com/authorize")
                                            .tokenUri("https://oauth.vk.com/access_token")
                                            .userNameAttributeName("email")
                                            .clientName("Vk")
                                            .build()
                            )
                    );
                    c.tokenEndpoint(cc ->
                            cc.accessTokenResponseClient(codeGrantRequestData -> {
                                var client = codeGrantRequestData.getClientRegistration();
                                var token = RestClient.create().get()
                                        .uri("""
                                                https://oauth.vk.com/access_token\
                                                ?client_id=%s&client_secret=%s\
                                                &redirect_uri=%s&code=%s"""
                                                .formatted(
                                                        client.getClientId(), client.getClientSecret(),
                                                        codeGrantRequestData.getAuthorizationExchange()
                                                                .getAuthorizationRequest().getRedirectUri(),
                                                        codeGrantRequestData.getAuthorizationExchange()
                                                                .getAuthorizationResponse().getCode()
                                                )
                                        )
                                        .retrieve().body(VkTokenResponse.class);

                                return OAuth2AccessTokenResponse
                                        .withToken(token.accessToken)
                                        .tokenType(OAuth2AccessToken.TokenType.BEARER)
                                        .additionalParameters(
                                                Map.of("vkId", token.userId, "email", token.email)
                                        )
                                        .build();
                            })
                    );
                    c.userInfoEndpoint(cc ->
                            cc.userService(userRequestData ->
                                    new DefaultOAuth2User(
                                            List.of(new SimpleGrantedAuthority("ROLE_USER")),
                                            userRequestData.getAdditionalParameters(), "email"
                                    )
                            )
                    );
                }).build();
    }
}
