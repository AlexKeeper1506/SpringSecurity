package com.example.springsecurity.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.firewall.*;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("456"))
                .roles("ADMIN")
                .build();

        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder.encode("123"))
                .roles("USER")
                .build();

        UserDetails alex = User.builder()
                .username("alex")
                .password(passwordEncoder.encode("789"))
                .roles("ADMIN", "USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user, alex);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers("/welcome")
                                .permitAll()
                                .requestMatchers("/admin")
                                .hasRole("ADMIN")
                                .requestMatchers("/**")
                                .authenticated()
                )
                .formLogin(AbstractAuthenticationFilterConfigurer::permitAll)
                .sessionManagement(
                        sessionConfigurer -> sessionConfigurer
                                .sessionConcurrency(
                                        concurrencyConfigurer -> concurrencyConfigurer
                                                .maximumSessions(1)
                                                .maxSessionsPreventsLogin(true)
                                )
                )
                .build();
    }

    @Bean
    public WebSecurityCustomizer globalSecurity() {
        return web -> web
                .requestRejectedHandler(
                        (request, response, exception) -> {
                            response.sendRedirect("/banned_referer");
                        }
                )
                .httpFirewall(
                        new StrictHttpFirewall() {
                            final List<String> whiteList = List.of(
                                    "http://localhost:8080",
                                    "http://localhost:8080/",
                                    "http://localhost:8080/login",
                                    "http://localhost:8080/admin",
                                    "http://localhost:8080/welcome",
                                    "http://localhost:8080/foo",
                                    "http://localhost:8080/banned_referer",
                                    "http://localhost:8080/?continue",
                                    "http://localhost:8080/login?continue",
                                    "http://localhost:8080/admin?continue",
                                    "http://localhost:8080/welcome?continue",
                                    "http://localhost:8080/foo?continue",
                                    "http://localhost:8080/banned_referer?continue",
                                    "http://localhost:8080/login?error"
                            );

                            @Override
                            public FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException {
                                String url     = request.getRequestURL().toString();
                                String referer = request.getHeader("referer");

                                System.out.println("URL = " + url);
                                System.out.println("referer " + referer);
                                if ((!url.equals("http://localhost:8080/banned_referer")) && (referer != null)) {
                                    if (!whiteList.contains(referer)) throw new RequestRejectedException("The referer is not included in the white list!");
                                }
                                System.out.println();

                                return super.getFirewalledRequest(request);
                             }
                        }
                );
    }
}
