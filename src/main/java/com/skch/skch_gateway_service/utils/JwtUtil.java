package com.skch.skch_gateway_service.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtUtil {

	private final JwtDecoder jwtDecoder;

//	@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
//	private String issuerUri;

	public JwtUtil(@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri) {
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation(issuerUri).build();
		decoder.setJwtValidator(token -> OAuth2TokenValidatorResult.success());
		this.jwtDecoder = decoder;
	}

	public String extractUserEmail(String token) {
		Jwt jwt = jwtDecoder.decode(token);
		return jwt.getSubject();
	}
	
	public String extractSid(String token) {
		Jwt jwt = jwtDecoder.decode(token);
		return jwt.getClaimAsString("sid");
	}

}
