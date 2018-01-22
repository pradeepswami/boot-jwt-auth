package com.sample.jwt.auth;


import com.boot.jwt.core.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;

@RestController
public class SampleController {


    @Autowired
    private JwtService jwtService;


    @RequestMapping("/hello/{name}")
    public String sayHello(@PathVariable String name) {
        System.err.println(SecurityContextHolder.getContext().getAuthentication());
        System.err.println(SecurityContextHolder.getContext().getAuthentication().getPrincipal());

        System.err.println(jwtService.generateToken(Collections.emptyMap()));


        return "Hello! " + name;
    }


    @RequestMapping("/secure/hello/{name}")
    public String unsecureSayHello(@PathVariable String name) {

        System.err.println(SecurityContextHolder.getContext().getAuthentication());

        return "Hello! " + name;
    }

}
