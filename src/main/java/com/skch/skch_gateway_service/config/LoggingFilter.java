package com.skch.skch_gateway_service.config;

import java.net.InetSocketAddress;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
public class LoggingFilter {

	@Bean
	public GlobalFilter globalLogFilter() {
		return (exchange, chain) -> {

			long startTime = System.currentTimeMillis();
			ServerHttpRequest request = exchange.getRequest();

			String path = request.getURI().getPath();
			String method = request.getMethod() != null ? request.getMethod().name() : "UNKNOWN";
			String clientIp = getClientIp(request);
			String userAgent = request.getHeaders().getFirst("User-Agent");

			return exchange.getPrincipal().cast(Authentication.class).map(this::extractuserName)
					.defaultIfEmpty("ANONYMOUS")
					.flatMap(userName -> {
						log.info("REQUEST : | {} {} | user={} | ip={} | ua={}", method, path, userName, clientIp, userAgent);
						return chain.filter(exchange).doFinally(signal -> {
							long duration = System.currentTimeMillis() - startTime;
							log.info("RESPONSE : | {} {} | status={} | time={}ms", method, path,
									exchange.getResponse().getStatusCode(), duration);
						});
					});
		};
	}

	private String extractuserName(Authentication auth) {
		if (auth instanceof JwtAuthenticationToken jwtAuth) {
			// Prefer a stable claim you control
			String userName = jwtAuth.getToken().getClaimAsString("sub");
			return userName != null ? userName : "UNKNOWN_USER";
		}
		return "ANONYMOUS";
	}

	private String getClientIp(ServerHttpRequest request) {
		String xForwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
		if (xForwardedFor != null && !xForwardedFor.isBlank()) {
			return xForwardedFor.split(",")[0].trim();
		}

		InetSocketAddress remoteAddress = request.getRemoteAddress();
		return remoteAddress != null ? remoteAddress.getAddress().getHostAddress() : "UNKNOWN";
	}
}