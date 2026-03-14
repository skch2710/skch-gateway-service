package com.skch.skch_gateway_service.config;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class CustomAccessDeniedHandler implements ServerAccessDeniedHandler {

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {

        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        
        var request = exchange.getRequest();
        var response = exchange.getResponse();

        String origin = request.getHeaders().getOrigin();
        if (origin != null) {
            response.getHeaders().add("Access-Control-Allow-Origin", origin);
            response.getHeaders().add("Access-Control-Allow-Credentials", "true");
            response.getHeaders().add("Access-Control-Allow-Headers", "Authorization, Content-Type");
        }
        
        String body = """
                {
                  "status": 403,
                  "error": "Forbidden",
                  "message": "Access denied"
                }
                """;

        var buffer = exchange.getResponse()
                .bufferFactory()
                .wrap(body.getBytes());

        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}