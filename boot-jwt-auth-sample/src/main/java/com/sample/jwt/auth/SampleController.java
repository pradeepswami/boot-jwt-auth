package com.sample.jwt.auth;


import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleController {


    @RequestMapping("/hello/{name}")
    public String sayHello(@PathVariable String name) {
        return "Hello! " + name;
    }


    @RequestMapping("/secure/hello/{name}")
    public String unsecureSayHello(@PathVariable String name) {
        return "Hello! " + name;
    }

}
