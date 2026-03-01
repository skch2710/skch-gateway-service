package com.skch.skch_gateway_service.config;

import java.net.InetSocketAddress;
import java.util.List;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.skch.skch_gateway_service.utils.JwtUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class LoggingAndSessionFilter {

	private static final String REDIS_KEY_PREFIX = "USER_SESSION:";
	private final JwtUtil jwtUtil;

	// Public paths – both unprefixed (as seen by the gateway) and prefixed
	private static final List<String> PUBLIC_PATHS = List.of("/authenticate/login", "/authenticate/logout", "/test",
			"/swagger-ui/", "/v3/api-docs/", "/webjars/", "/apiService/authenticate/login",
			"/apiService/authenticate/logout", "/apiService/test", "/apiService/v3/api-docs/");

	private final ReactiveStringRedisTemplate redisTemplate;
	private final ObjectMapper objectMapper = new ObjectMapper();

	@Bean
	@Order(-1)
	public GlobalFilter combinedFilter() {
		return (exchange, chain) -> {

			long startTime = System.currentTimeMillis();

			// Extract request details
			ServerHttpRequest request = exchange.getRequest();
			String path = request.getURI().getPath();
			String method = request.getMethod() != null ? request.getMethod().name() : "UNKNOWN";
			String clientIp = getClientIp(request);
			String userAgent = request.getHeaders().getFirst("User-Agent");

			MultiValueMap<String, HttpCookie> cookies = exchange.getRequest().getCookies();
			HttpCookie cookie = cookies.getFirst("ACCESS_TOKEN");
			String tokenValue = cookie != null ? cookie.getValue() : "NO_COOKIE";

			// ----- Public path handling -----
			if (isPublicPath(path)) {
				log.info("REQUEST : | {} {} | user=ANONYMOUS | ip={} | ua={}", method, path, clientIp, userAgent);
				return chain.filter(exchange).doFinally(signalType -> {
					long duration = System.currentTimeMillis() - startTime;
					log.info("RESPONSE : | {} {} | status={} | time={}ms", method, path,
							exchange.getResponse().getStatusCode(), duration);
				});
			}

			// ----- Protected path handling -----
			return validateSession(exchange, tokenValue, chain, startTime, method, path);

		};
	}

	private boolean isPublicPath(String path) {
		return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
	}

	private String getClientIp(ServerHttpRequest request) {
		String xForwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
		if (xForwardedFor != null && !xForwardedFor.isBlank()) {
			return xForwardedFor.split(",")[0].trim();
		}
		InetSocketAddress remoteAddress = request.getRemoteAddress();
		return remoteAddress != null ? remoteAddress.getAddress().getHostAddress() : "UNKNOWN";
	}

	private Mono<Void> validateSession(ServerWebExchange exchange, String token, GatewayFilterChain chain,
			long startTime, String method, String path) {

		String userId = jwtUtil.extractUserEmail(token);

		log.info("REQUEST : | {} {} | user={} | ip={} | ua={} | token={}", exchange.getRequest().getMethod(),
				exchange.getRequest().getURI().getPath(), userId, getClientIp(exchange.getRequest()),
				exchange.getRequest().getHeaders().getFirst("User-Agent"), token);

		String jwtSid = jwtUtil.extractSid(token);

		if (jwtSid == null || jwtSid.isBlank()) {
			log.warn("Missing sid for user: {}", userId);
			return unauthorized(exchange, "Missing session id");
		}

		String redisKey = REDIS_KEY_PREFIX + userId;

		log.info("Checking Redis for key: {}", redisKey);

		return redisTemplate.opsForValue().get(redisKey).flatMap(storedSid -> {
			if (storedSid != null && jwtSid.equals(storedSid)) {
				log.info("Session validated for user: {}. sid: {}", userId, jwtSid);
				return chain.filter(exchange).doFinally(signalType -> {
					long duration = System.currentTimeMillis() - startTime;
					log.info("RESPONSE : | {} {} | status={} | time={}ms", method, path,
							exchange.getResponse().getStatusCode(), duration);
				});
			} else {
				log.warn("Session mismatch for user: {}. Expected sid: {}, but got: {}", userId, storedSid, jwtSid);
				return unauthorized(exchange, "Session mismatch");
			}
		});
	}

	private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
		exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
		exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
		try {
			ErrorResponse error = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), "Unauthorized", message);
			byte[] bytes = objectMapper.writeValueAsBytes(error);
			DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
			return exchange.getResponse().writeWith(Mono.just(buffer));
		} catch (JsonProcessingException e) {
			log.error("Error creating error response", e);
			return exchange.getResponse().setComplete();
		}
	}

	private record ErrorResponse(int status, String error, String message) {
	}
}
