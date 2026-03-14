package com.skch.skch_gateway_service.config;

import java.time.Duration;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	
	@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
	String issuerUri;
	
	private static final String JWT_ROLE_NAME = "authorities";
	private static final String ROLE_PREFIX = "";
	
	private final CustomAuthenticationEntryPoint authenticationEntryPoint;
	private final CustomAccessDeniedHandler accessDeniedHandler;

	@Bean
	SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
		return http
				.cors(Customizer.withDefaults()) 
				.csrf(ServerHttpSecurity.CsrfSpec::disable)
				.authorizeExchange(auth -> auth.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
						.pathMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**", "/swagger-resources/**",
								"/webjars/**", "/apiService/swagger-ui/**", "/apiService/v3/api-docs/**")
						.permitAll().pathMatchers("/apiService/authenticate/**", "/apiService/test/**", "/auth/**")
						.permitAll().anyExchange().authenticated())
				.oauth2ResourceServer(
						oauth2 -> oauth2
								.authenticationEntryPoint(authenticationEntryPoint)
								.accessDeniedHandler(accessDeniedHandler)
//								.bearerTokenConverter(exchange -> {
//							        String path = exchange.getRequest().getURI().getPath();
//							        if (path.contains("/authenticate/refresh")) {
//							            return Mono.empty();
//							        }
//							        return new ServerBearerTokenAuthenticationConverter().convert(exchange);
//							    })
								.jwt(jwt -> jwt.jwtDecoder(jwtDecoder()).jwtAuthenticationConverter(
										new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter()))))
				.build();
	}
	
	@Bean
	public ReactiveJwtDecoder jwtDecoder() {
		NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withIssuerLocation(issuerUri).build();
		JwtTimestampValidator timestampValidator = new JwtTimestampValidator(Duration.ZERO);
		OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(
				JwtValidators.createDefaultWithIssuer(issuerUri), timestampValidator);
		decoder.setJwtValidator(validator);
		return decoder;
	}

	private JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName(JWT_ROLE_NAME);
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix(ROLE_PREFIX);
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
		return jwtAuthenticationConverter;

	}

	@Bean
	public KeyResolver ipKeyResolver() {
		return exchange -> Mono
				.just(Objects.requireNonNull(exchange.getRequest().getRemoteAddress()).getAddress().getHostAddress());
	}

}