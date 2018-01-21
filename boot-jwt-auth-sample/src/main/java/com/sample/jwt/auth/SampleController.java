package com.sample.jwt.auth;


import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleController {


    @RequestMapping("/hello/{name}")
    public String sayHello(@PathVariable String name) {
        System.err.println(SecurityContextHolder.getContext().getAuthentication());
        System.err.println(SecurityContextHolder.getContext().getAuthentication().getPrincipal());

        return "Hello! " + name;
    }


    @RequestMapping("/secure/hello/{name}")
    public String unsecureSayHello(@PathVariable String name) {

        System.err.println(SecurityContextHolder.getContext().getAuthentication());

        return "Hello! " + name;
    }

}
