package com.skch.skch_gateway_service.config;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.UUID;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
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
    private static final String FILTER_MARKER_HEADER = "X-Gateway-Filter-Marker";
    private static final String START_TIME_ATTR = "start.time";
    private static final String LOG_ENABLED_ATTR = "log.enabled";

    // Public paths – both unprefixed (as seen by the gateway) and prefixed
    private static final List<String> PUBLIC_PATHS = List.of(
        "/authenticate/login",
        "/authenticate/logout",
        "/authenticate/refresh",
        "/test",
        "/swagger-ui/",
        "/v3/api-docs/",
        "/webjars/",
        "/apiService/authenticate/login",
        "/apiService/authenticate/logout",
        "/apiService/authenticate/refresh",
        "/apiService/test",
        "/apiService/v3/api-docs/"
    );

    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Bean
    @Order(-1)
    public GlobalFilter combinedFilter() {
        return (exchange, chain) -> {
            // Determine if this is the first execution using a marker header
            String headerMarker = exchange.getRequest().getHeaders().getFirst(FILTER_MARKER_HEADER);
            boolean isFirstExecution = (headerMarker == null);

            // Build the exchange to use (add marker on first execution)
            final ServerWebExchange finalExchange;
            if (isFirstExecution) {
                String newMarker = UUID.randomUUID().toString();
                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                        .header(FILTER_MARKER_HEADER, newMarker)
                        .build();
                finalExchange = exchange.mutate().request(mutatedRequest).build();
                finalExchange.getAttributes().put(FILTER_MARKER_HEADER, newMarker);
            } else {
                finalExchange = exchange;
            }

            // Store start time
            long startTime = System.currentTimeMillis();
            finalExchange.getAttributes().put(START_TIME_ATTR, startTime);

            // Extract request details
            ServerHttpRequest request = finalExchange.getRequest();
            String path = request.getURI().getPath();
            String method = request.getMethod() != null ? request.getMethod().name() : "UNKNOWN";
            String clientIp = getClientIp(request);
            String userAgent = request.getHeaders().getFirst("User-Agent");

            // ----- Public path handling -----
            if (isPublicPath(path)) {
                // Only log request on first execution
                if (isFirstExecution) {
                    log.info("REQUEST : | {} {} | user=ANONYMOUS | ip={} | ua={}", method, path, clientIp, userAgent);
                    finalExchange.getAttributes().put(LOG_ENABLED_ATTR, true);
                }
                return chain.filter(finalExchange)
                        .doFinally(signalType -> logResponseIfEnabled(finalExchange, method, path));
            }

            // ----- Protected path handling -----
            return ReactiveSecurityContextHolder.getContext()
                    .map(ctx -> ctx.getAuthentication())
                    .flatMap(auth -> {
                        String userName = extractUserName(auth);
                        // Only log request if we have a user (i.e., authenticated) – this prevents the second "ANONYMOUS" log
                        if (!"ANONYMOUS".equals(userName)) {
                            log.info("REQUEST : | {} {} | user={} | ip={} | ua={}", method, path, userName, clientIp, userAgent);
                            finalExchange.getAttributes().put(LOG_ENABLED_ATTR, true);
                        }
                        // Proceed with session validation if needed
                        if (auth instanceof JwtAuthenticationToken jwtAuth) {
                            return validateSession(jwtAuth, finalExchange, chain);
                        }
                        return chain.filter(finalExchange);
                    })
                    .switchIfEmpty(Mono.defer(() -> {
                        // No security context – do not log request (avoids duplicate anonymous logs)
                        // But still need to continue the chain
                        return chain.filter(finalExchange);
                    }))
                    .doFinally(signalType -> logResponseIfEnabled(finalExchange, method, path));
        };
    }

    /** Log response only if this execution logged the request */
    private void logResponseIfEnabled(ServerWebExchange exchange, String method, String path) {
        Boolean logEnabled = exchange.getAttribute(LOG_ENABLED_ATTR);
        if (logEnabled != null && logEnabled) {
            Long start = exchange.getAttribute(START_TIME_ATTR);
            if (start != null) {
                long duration = System.currentTimeMillis() - start;
                log.info("RESPONSE : | {} {} | status={} | time={}ms",
                        method, path, exchange.getResponse().getStatusCode(), duration);
            }
        }
    }

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
                                        GatewayFilterChain chain) {
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