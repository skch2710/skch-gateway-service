package com.skch.skch_gateway_service.exception;

import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.databind.ObjectMapper;

import reactor.core.publisher.Mono;

@Component
@Order(-2)
public class GlobalExceptionHandler implements ErrorWebExceptionHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {

        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String message = "An unexpected error occurred.";

        if (ex instanceof AccessDeniedException) {
            status = HttpStatus.FORBIDDEN;
            message = "ACCESS_DENIED";
        } 
        else if (ex instanceof InvalidBearerTokenException) {
            status = HttpStatus.UNAUTHORIZED;
            message = "Invalid access token.";
        } 
        else if (ex instanceof InsufficientAuthenticationException) {
            status = HttpStatus.UNAUTHORIZED;
            message = "Full authentication is required.";
        } 
        else if (ex instanceof MissingCsrfTokenException) {
            status = HttpStatus.UNAUTHORIZED;
            message = "CSRF token is missing.";
        } 
        else if (ex instanceof InvalidCsrfTokenException) {
            status = HttpStatus.UNAUTHORIZED;
            message = "Invalid CSRF token.";
        }

        ErrorResponse response = new ErrorResponse();
        response.setStatusCode(status.value());
        response.setSuccessMessage(message);
        response.setErrorMessage(ex.getMessage());

        ServerHttpResponse httpResponse = exchange.getResponse();
        httpResponse.setStatusCode(status);
        httpResponse.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(response);
            return httpResponse.writeWith(
                    Mono.just(httpResponse.bufferFactory().wrap(bytes))
            );
        } catch (Exception e) {
            return Mono.error(e);
        }
    }
}