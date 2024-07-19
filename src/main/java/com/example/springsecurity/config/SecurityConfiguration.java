package com.example.springsecurity.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.firewall.*;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("""
                        ROLE_ADMIN > PERMISSION_INDEX
                        ROLE_ADMIN > PERMISSION_ROUTE1
                        ROLE_ADMIN > PERMISSION_ROUTE2
                        ROLE_USER > PERMISSION_INDEX
                        ROLE_USER > PERMISSION_ROUTE2
                        """
        );
        return hierarchy;
    }
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setRoleHierarchy(roleHierarchy);
        return expressionHandler;
    }

    @Bean
    public PasswordEncoder createDelegatingPasswordEncoder() {
        String encodingId = "bcrypt";
        Map<String, PasswordEncoder> encoders = new HashMap<>();

        encoders.put(encodingId, new BCryptPasswordEncoder());

        return new DelegatingPasswordEncoder(encodingId, encoders);
    }

    @Bean
    public JdbcUserDetailsManager userDetailsService(DataSource dataSource) {
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);
        manager.setEnableGroups(true);
        return manager;
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, PersistentTokenRepository repository) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers("/welcome")
                                .permitAll()
                                .requestMatchers("/foo2")
                                .permitAll()
                                .requestMatchers("/admin")
                                .hasRole("ADMIN")
                                .requestMatchers("/**")
                                .authenticated()
                )
                .formLogin(
                        formLogin -> formLogin
                                .defaultSuccessUrl("/", true)
                )
                .rememberMe(
                        rememberMe -> {
                            rememberMe.tokenRepository(repository);
                            rememberMe.key("0xCAFEBABE0xDEADBABE0xBA0BAB");
                        }
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
                                    "http://localhost:8080/login?error",
                                    "http://localhost:8080/create_users"
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
