package com.skch.skch_gateway_service.exception;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CustomException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private String message;
	private HttpStatus status;

//  public CustomException(String message, HttpStatus status) {
//    super();
//    this.message = message;
//    this.status = status;
//  }
//
//  public String getMessage() {
//    return message;
//  }
//
//  public void setMessage(String message) {
//    this.message = message;
//  }
//
//  public HttpStatus getStatus() {
//    return status;
//  }
//
//  public void setStatus(HttpStatus status) {
//    this.status = status;
//  }

}
