package com.skch.skch_gateway_service.config;

import java.util.Objects;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

	@Bean
	SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	    return http
	            .csrf(ServerHttpSecurity.CsrfSpec::disable)
	            .cors(Customizer.withDefaults())
	            .authorizeExchange(auth -> auth

	                    // ✅ Allow preflight
	                    .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()

	                    // ✅ Allow Swagger completely
	                    .pathMatchers(
	                            "/swagger-ui/**",
	                            "/v3/api-docs/**",
	                            "/webjars/**",
	                            "/apiService/v3/api-docs/**"
	                    ).permitAll()

	                    // ✅ Allow login/auth endpoints
	                    .pathMatchers(
	                            "/apiService/authenticate/**",
	                            "/apiService/test/**",
	                            "/auth/**"
	                    ).permitAll()

	                    // 🔐 Everything else protected
	                    .anyExchange().authenticated()
	            )
	            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
	            .build();
	}
	
	@Bean
	public KeyResolver ipKeyResolver() {
		return exchange -> Mono
				.just(Objects.requireNonNull(exchange.getRequest()
				.getRemoteAddress()).getAddress().getHostAddress());
	}

}