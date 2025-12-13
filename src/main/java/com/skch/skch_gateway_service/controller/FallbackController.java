package com.skch.skch_gateway_service.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FallbackController {

	@GetMapping("/fallback/api")
	public ResponseEntity<String> apiFallback() {
		return ResponseEntity.status(503).body("API Service is unavailable. Please try again later.");
	}
}
