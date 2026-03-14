package com.skch.skch_gateway_service.config;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class CustomAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {

        var request = exchange.getRequest();
        var response = exchange.getResponse();

        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // 🔥 ADD THESE LINES
        String origin = request.getHeaders().getOrigin();
        if (origin != null) {
            response.getHeaders().add("Access-Control-Allow-Origin", origin);
            response.getHeaders().add("Access-Control-Allow-Credentials", "true");
            response.getHeaders().add("Access-Control-Allow-Headers", "Authorization, Content-Type");
        }

        String body = """
                {
                  "status": 401,
                  "error": "Unauthorized",
                  "message": "Invalid or expired token"
                }
                """;

        var buffer = response.bufferFactory().wrap(body.getBytes());

        return response.writeWith(Mono.just(buffer));
    }
}