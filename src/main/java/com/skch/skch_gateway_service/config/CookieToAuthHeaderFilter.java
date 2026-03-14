package com.skch.skch_gateway_service.config;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CookieToAuthHeaderFilter implements WebFilter {

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

		var cookies = exchange.getRequest().getCookies();
		var cookie = cookies.getFirst("ACCESS_TOKEN");
		
		String path = exchange.getRequest().getURI().getPath();
		
		if(path.contains("/login") || path.contains("/refresh") || path.contains("/logout")) {
			return chain.filter(exchange);
		}
		
		if (cookie != null && cookie.getValue() != null && !cookie.getValue().isBlank()) {
			log.info("Found ACCESS_TOKEN cookie, adding Authorization header for path: {}", path);
			ServerWebExchange mutated = exchange.mutate()
					.request(r -> r.header(HttpHeaders.AUTHORIZATION, "Bearer " + cookie.getValue()))
					.build();
			return chain.filter(mutated);
		}
		
		
		return chain.filter(exchange);
	}
}
