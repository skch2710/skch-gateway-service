package com.skch.skch_gateway_service.config;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class SingleLoginGatewayFilter {

	private static final String REDIS_KEY_PREFIX = "USER_SESSION:";

	private final ReactiveStringRedisTemplate redisTemplate;

	@Bean
	public GlobalFilter singleLoginFilter() {
		return (exchange, chain) -> exchange.getPrincipal()
				// Apply only for authenticated requests
				.filter(p -> p instanceof JwtAuthenticationToken).cast(JwtAuthenticationToken.class)
				.flatMap(jwtAuth -> validateSession(jwtAuth, exchange, chain))
				// Public APIs (no JWT)
				.switchIfEmpty(chain.filter(exchange));
	}

	private Mono<Void> validateSession(JwtAuthenticationToken jwtAuth, ServerWebExchange exchange,
			GatewayFilterChain chain) {

		String userId = jwtAuth.getToken().getSubject(); // sub
		String jwtSid = jwtAuth.getToken().getClaimAsString("sid");

		if (jwtSid == null) {
			return unauthorized(exchange);
		}

		String redisKey = REDIS_KEY_PREFIX + userId;

		return redisTemplate.opsForValue().get(redisKey).flatMap(redisSid -> {
			log.info("Validating session for userId={} with jwtSid={} against redisSid={}", userId, jwtSid, redisSid);
			if (!jwtSid.equals(redisSid)) {
				return unauthorized(exchange);
			}
			return chain.filter(exchange);
		})
			.switchIfEmpty(unauthorized(exchange));
	}

	private Mono<Void> unauthorized(ServerWebExchange exchange) {
		exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
		return exchange.getResponse().setComplete();
	}
}
