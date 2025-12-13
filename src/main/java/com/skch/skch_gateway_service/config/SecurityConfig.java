package com.skch.skch_gateway_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(auth -> auth
                        .pathMatchers("/api/authenticate/**").permitAll()   // PUBLIC
                        .pathMatchers(
                                "/swagger/api/**",
                                "/swagger/api/v3/api-docs/**",
                                "/swagger/api/swagger-ui/**",
                                "/swagger/api/swagger-resources/**",
                                "/swagger/api/webjars/**"
                        ).permitAll()
                        .pathMatchers("/auth/**").permitAll()               // PUBLIC AUTH ENDPOINTS
                        .anyExchange().authenticated()                      // ALL OTHER ROUTES SECURED
                )
                .oauth2ResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec::jwt)
                .build();
    }
}