//package com.skch.skch_gateway_service.config;
//
//import org.springframework.cloud.gateway.filter.GlobalFilter;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.core.io.buffer.DataBuffer;
//import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.MediaType;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.ReactiveSecurityContextHolder;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
//import org.springframework.web.server.ServerWebExchange;
//
//import com.fasterxml.jackson.core.JsonProcessingException;
//import com.fasterxml.jackson.databind.ObjectMapper;
//
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import reactor.core.publisher.Mono;
//
//@Slf4j
//@Configuration
//@RequiredArgsConstructor
//public class SingleLoginGatewayFilter {
//
//    private static final String REDIS_KEY_PREFIX = "USER_SESSION:";
//    private final ReactiveStringRedisTemplate redisTemplate;
//    private final ObjectMapper objectMapper = new ObjectMapper();
//
//    @Bean
//    @Order(0) // Set order to ensure it runs once
//    public GlobalFilter singleLoginFilter() {
//        return (exchange, chain) -> {
//            // Add a flag to prevent double execution
//            if (exchange.getAttribute("single-login-filter-executed") != null) {
//                log.debug("Filter already executed for this request, skipping");
//                return chain.filter(exchange);
//            }
//            
//            exchange.getAttributes().put("single-login-filter-executed", true);
//            
//            return ReactiveSecurityContextHolder.getContext()
//                .flatMap(securityContext -> {
//                    Authentication authentication = securityContext.getAuthentication();
//                    
//                    if (!(authentication instanceof JwtAuthenticationToken jwtAuth)) {
//                        return chain.filter(exchange);
//                    }
//                    
//                    return validateSession(jwtAuth, exchange, chain);
//                })
//                .switchIfEmpty(chain.filter(exchange));
//        };
//    }
//
//    private Mono<Void> validateSession(
//            JwtAuthenticationToken jwtAuth,
//            ServerWebExchange exchange,
//            org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {
//
//        String userId = jwtAuth.getToken().getSubject();
//        String jwtSid = jwtAuth.getToken().getClaimAsString("sid");
//
//        if (jwtSid == null || jwtSid.isBlank()) {
//            return unauthorized(exchange, "Missing session ID in token");
//        }
//
//        String redisKey = REDIS_KEY_PREFIX + userId;
//
//        return redisTemplate.opsForValue()
//            .get(redisKey)
//            .flatMap(redisSid -> {
//                if (!jwtSid.equals(redisSid)) {
//                    return unauthorized(exchange, "Session expired or invalid");
//                }
//                return chain.filter(exchange);
//            })
//            .switchIfEmpty(Mono.defer(() -> 
//                unauthorized(exchange, "No active session found")
//            ));
//    }
//
//    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
//        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
//        
//        try {
//            ErrorResponse errorResponse = new ErrorResponse(
//                HttpStatus.UNAUTHORIZED.value(),
//                "Unauthorized",
//                message
//            );
//            
//            byte[] bytes = objectMapper.writeValueAsBytes(errorResponse);
//            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
//            return exchange.getResponse().writeWith(Mono.just(buffer));
//        } catch (JsonProcessingException e) {
//            log.error("Error creating error response", e);
//            return exchange.getResponse().setComplete();
//        }
//    }
//
//    private record ErrorResponse(int status, String error, String message) {}
//}