package com.jade.platform.config;

import com.jade.platform.config.context.AdSecurityContextRepository;
import com.jade.platform.config.provider.AdJwtAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * @Author: Josiah Adetayo
 * @Email: josiah.adetayo@sabi.am
 * @Date: 5/11/24
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@RequiredArgsConstructor
public class ResourceServer {

    private final AdJwtAuthenticationProvider provider;
    private final AdSecurityContextRepository contextRepository;

    @Bean
    public SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {

        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authenticationManager(provider)
                .securityContextRepository(contextRepository)
                .authorizeExchange(authorizeExchangeSpec ->
                        authorizeExchangeSpec
                                .pathMatchers(AUTH_WHITELIST)
                                .permitAll()
                                .anyExchange()
                                .authenticated()
                );
        return http.build();
    }

    private static final String[] AUTH_WHITELIST = {
            "/v1/banks",
            "/v1/banks/**",
            "/v1/bank/customers",
            "/v1/methods/types",
            "/v1/methods/_public",
            "/v1/payment/webhook",
            // other public endpoints of your API may be appended to this array
    };

}
