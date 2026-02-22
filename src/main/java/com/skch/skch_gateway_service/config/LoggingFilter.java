package com.skch.skch_gateway_service.config;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
public class LoggingFilter {

	@Bean
	public GlobalFilter globalLogFilter() {
		return (exchange, chain) -> {
			log.info("Incoming request --> " + exchange.getRequest().getPath());
			return chain.filter(exchange).then(Mono.fromRunnable(
					() -> log.info("Response status --> " + exchange.getResponse().getStatusCode())));
		};
	}
}
