package com.jade.platform.controller;

import jakarta.annotation.PostConstruct;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

/**
 * @Author: Josiah Adetayo
 * @Email: josleke@gmail.com, josiah.adetayo@meld-tech.com
 * @Date: 5/12/24
 */
@RestController
public class HomeController {

    @GetMapping("/demo/user")
//    @PreAuthorize("hasAuthority('readUser')")
    public Mono<String> user() {
        return Mono.just("User read success.");
    }

    @PostMapping("/demo/user")
//    @PreAuthorize("hasAuthority('updateUser')")
    public Mono<String> addAser(@RequestBody String userData) {
        return Mono.just(userData + "User read success.");
    }
}
