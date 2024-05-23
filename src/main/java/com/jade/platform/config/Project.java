package com.jade.platform.config;

import com.jade.platform.config.decoder.AdNimbusJwtDecoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * @Author: Josiah Adetayo
 * @Email: josiah.adetayo@sabi.am
 * @Date: 5/23/24
 */
@Configuration
public class Project {
    @Bean
    public JwtDecoder jwtDecoder() {
        return new AdNimbusJwtDecoder();
    }
}
