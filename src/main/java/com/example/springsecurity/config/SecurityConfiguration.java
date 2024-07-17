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
                //.formLogin().disable()
                .formLogin(AbstractAuthenticationFilterConfigurer::permitAll)
                /*.exceptionHandling(
                        c -> c.authenticationEntryPoint(
                                (request, response, authException) -> {}
                        )
                )*/
                .build();
    }

    @Bean
    public WebSecurityCustomizer globalSecurity() {
        return web -> web
                .requestRejectedHandler(
                        //new HttpStatusRequestRejectedHandler()
                        (request, response, exception) -> {
                            response.sendError(402, "Test message!");
                        }
                )
                .httpFirewall(
                new StrictHttpFirewall() {
                    @Override
                    public FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException {
                        throw new RequestRejectedException("Test reason");
                        //return super.getFirewalledRequest(request);
                    }
                }
        );
    }
    /*@Bean
    public HttpFirewall configureFirewall() {
        StrictHttpFirewall strictHttpFirewall = new StrictHttpFirewall();
        strictHttpFirewall.setAllowBackSlash(true);
        strictHttpFirewall.setAllowedHttpMethods(Arrays.asList("GET", "POST", "DELETE", "OPTIONS"));
        //strictHttpFirewall.setAllowedHeaderValues(x -> x.equals("https://www.test.com"));
        return strictHttpFirewall;
    }*/
}
