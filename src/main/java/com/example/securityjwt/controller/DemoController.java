package com.example.securityjwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author vienlv
 */
@RestController
@RequestMapping(value = "/api/v1/demo")
public class DemoController {

    @GetMapping("/")
    public ResponseEntity<String> demo() {
        return ResponseEntity.ok("helloDemo");
    }
}
