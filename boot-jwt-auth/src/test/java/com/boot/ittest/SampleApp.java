package com.boot.ittest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.boot.jwt.configuration.EnableJwtAuthentication;

@EnableJwtAuthentication
@SpringBootApplication
public class SampleApp {

	public static void main(String[] args) {
		SpringApplication.run(SampleApp.class, args);
	}

	@RestController
	public static class HelloController {

		@RequestMapping("/hello")
		public String hello() {
			System.err.println("In hello");
			return "Hello! from SampleApp";
		}

		@RequestMapping("/unsecure/hello")
		public String unsecureHello() {
			System.err.println("In unsecureHello");
			return "Hello! from SampleApp - Unsecure";
		}

	}

}
