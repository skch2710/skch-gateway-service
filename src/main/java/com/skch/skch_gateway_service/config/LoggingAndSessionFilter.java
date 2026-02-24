package com.skch.skch_gateway_service.config;

import java.net.InetSocketAddress;
import java.util.List;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class LoggingAndSessionFilter {

    private static final String REDIS_KEY_PREFIX = "USER_SESSION:";
    private static final String FILTER_EXECUTED = "logging.session.filter.executed";
    private static final String START_TIME_ATTR = "start.time";

    // ✅ List of public path prefixes – adjust to match your actual endpoints
    private static final List<String> PUBLIC_PATHS = List.of(
        "/apiService/authenticate/login",
        "/apiService/test",
        "/swagger-ui/**",
        "/v3/api-docs/**",
        "/webjars/**",
        "/apiService/v3/api-docs/**"
    );

    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Bean
    @Order(-1)
    public GlobalFilter combinedFilter() {
        return (exchange, chain) -> {
            // 🛡️ Guard against double execution (critical fix)
            if (exchange.getAttribute(FILTER_EXECUTED) != null) {
                return chain.filter(exchange);
            }
            exchange.getAttributes().put(FILTER_EXECUTED, true);

            // Store start time for response logging
            long startTime = System.currentTimeMillis();
            exchange.getAttributes().put(START_TIME_ATTR, startTime);

            // Extract request details
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();
            String method = request.getMethod() != null ? request.getMethod().name() : "UNKNOWN";
            String clientIp = getClientIp(request);
            String userAgent = request.getHeaders().getFirst("User-Agent");

            // ✅ If the path is public, skip all authentication/validation logic
            if (isPublicPath(path)) {
                log.info("REQUEST : | {} {} | user=ANONYMOUS | ip={} | ua={}", method, path, clientIp, userAgent);
                return chain.filter(exchange)
                        .doFinally(signalType -> {
                            long duration = System.currentTimeMillis() - startTime;
                            log.info("RESPONSE : | {} {} | status={} | time={}ms",
                                    method, path, exchange.getResponse().getStatusCode(), duration);
                        });
            }

            // For protected paths, continue with authentication‑based handling
            return ReactiveSecurityContextHolder.getContext()
                    .map(ctx -> ctx.getAuthentication())
                    .flatMap(auth -> {
                        String userName = extractUserName(auth);
                        log.info("REQUEST : | {} {} | user={} | ip={} | ua={}", method, path, userName, clientIp, userAgent);

                        if (auth instanceof JwtAuthenticationToken jwtAuth) {
                            return validateSession(jwtAuth, exchange, chain);
                        }
                        return chain.filter(exchange);
                    })
                    .switchIfEmpty(Mono.defer(() -> {
                        // No security context – should not happen for protected paths, but handle gracefully
                        log.info("REQUEST : | {} {} | user=ANONYMOUS | ip={} | ua={}", method, path, clientIp, userAgent);
                        return chain.filter(exchange);
                    }))
                    .doFinally(signalType -> {
                        Long start = exchange.getAttribute(START_TIME_ATTR);
                        if (start != null) {
                            long duration = System.currentTimeMillis() - start;
                            log.info("RESPONSE : | {} {} | status={} | time={}ms",
                                    method, path, exchange.getResponse().getStatusCode(), duration);
                        }
                    });
        };
    }

    /** Check if the request path matches any public prefix */
    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith);
    }

    private String extractUserName(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
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

    private Mono<Void> validateSession(JwtAuthenticationToken jwtAuth,
                                        ServerWebExchange exchange,
                                        org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {
        String userId = jwtAuth.getToken().getSubject();
        String jwtSid = jwtAuth.getToken().getClaimAsString("sid");

        if (jwtSid == null || jwtSid.isBlank()) {
            log.warn("Missing sid for user: {}", userId);
            return unauthorized(exchange, "Missing session id");
        }

        String redisKey = REDIS_KEY_PREFIX + userId;

        return redisTemplate.opsForValue().get(redisKey)
                .flatMap(redisSid -> {
                    if (redisSid == null) {
                        log.warn("No Redis session for user: {}", userId);
                        return unauthorized(exchange, "No active session");
                    }
                    if (!jwtSid.equals(redisSid)) {
                        log.warn("Session mismatch for user: {}", userId);
                        return unauthorized(exchange, "Session expired");
                    }
                    log.debug("Session valid for user: {}", userId);
                    return chain.filter(exchange);
                });
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        try {
            ErrorResponse error = new ErrorResponse(
                HttpStatus.UNAUTHORIZED.value(),
                "Unauthorized",
                message
            );
            byte[] bytes = objectMapper.writeValueAsBytes(error);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        } catch (JsonProcessingException e) {
            log.error("Error creating error response", e);
            return exchange.getResponse().setComplete();
        }
    }

    private record ErrorResponse(int status, String error, String message) {}
}