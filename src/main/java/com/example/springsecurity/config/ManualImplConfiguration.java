package com.example.springsecurity.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.client.RestClient;

import java.security.SecureRandom;

import static com.example.springsecurity.oath2.ManualImplementation.*;

@Configuration
public class ManualImplConfiguration {
    //@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        var random = new SecureRandom();
        var contextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
        var securityContextRepository = new HttpSessionSecurityContextRepository();

        var fc = http
                .authorizeHttpRequests(c -> c
                        .requestMatchers("/**").authenticated()
                )
                .exceptionHandling(c -> c
                        .authenticationEntryPoint(
                                (request, response, authException) -> {
                                    var state = random.nextLong();

                                    request.getSession().
                                            setAttribute(OAUTH_SESSION_STATE_ATTRIB, state);

                                    response.sendRedirect("""
                                            https://oauth.vk.com/authorize\
                                            ?client_id=%s&redirect_uri=%s\
                                            &scope=email&response_type=code\
                                            &state=%d&v=5.131\
                                            """.formatted(VK_OAUTH_CLIENT_ID, OAUTH_REDIRECT_URL, state)
                                    );
                                }
                        )
                )
                .addFilterAfter(
                        (request, response, filterChain) -> {
                            if (
                                    ((HttpServletRequest) request).getServletPath()
                                            .equals(OAUTH_REDIRECT_PATH)
                            ) {
                                var code = request.getParameter("code");
                                var state = Long.parseLong(request.getParameter("state"));
                                var originalState = (long) ((HttpServletRequest) request).getSession()
                                        .getAttribute(OAUTH_SESSION_STATE_ATTRIB);

                                ((HttpServletRequest) request).getSession().
                                        setAttribute(OAUTH_SESSION_STATE_ATTRIB, null);

                                if (state != originalState)
                                    throw new RuntimeException("state mismatch");

                                var token = RestClient.create().get()
                                        .uri("""
                                                https://oauth.vk.com/access_token\
                                                ?client_id=%s&client_secret=%s\
                                                &redirect_uri=%s&code=%s"""
                                                .formatted(
                                                        VK_OAUTH_CLIENT_ID, VK_OAUTH_CLIENT_SECRET,
                                                        OAUTH_REDIRECT_URL, code
                                                )
                                        )
                                        .retrieve().body(VkTokenResponse.class);

                                var context = contextHolderStrategy.createEmptyContext();
                                var authentication = new VkAuthenticationToken(token.email, token.userId);
                                context.setAuthentication(authentication);

                                contextHolderStrategy.setContext(context);
                                securityContextRepository.saveContext(
                                        context, (HttpServletRequest) request, (HttpServletResponse) response
                                );

                                var next = new SavedRequestAwareAuthenticationSuccessHandler();
                                next.onAuthenticationSuccess(
                                        (HttpServletRequest) request, (HttpServletResponse) response, authentication
                                );

                                return;
                            }

                            filterChain.doFilter(request, response);
                        },
                        LogoutFilter.class
                )
                .build();

        return fc;
    }
}
