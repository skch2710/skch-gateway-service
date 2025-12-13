package com.skch.skch_gateway_service.config;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

@Configuration
public class LoggingFilter {

	@Bean
	public GlobalFilter globalLogFilter() {
		return (exchange, chain) -> {
			System.out.println("Incoming request --> " + exchange.getRequest().getPath());
			return chain.filter(exchange).then(Mono.fromRunnable(
					() -> System.out.println("Response status --> " + exchange.getResponse().getStatusCode())));
		};
	}
}
