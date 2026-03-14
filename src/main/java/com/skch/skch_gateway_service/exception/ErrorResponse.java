package com.skch.skch_gateway_service.exception;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ErrorResponse {

  private int statusCode;
  private String successMessage;
  private String errorMessage;
}
