package com.boot.jwt;

import com.boot.jwt.configuration.EnableJwtAuthentication;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

        @RequestMapping("/hello2")
        public String hello2() {
            System.err.println("In hello2");
            return "Hello! from SampleApp";
        }

    }

}
