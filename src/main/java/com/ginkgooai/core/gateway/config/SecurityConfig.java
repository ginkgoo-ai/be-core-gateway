package com.ginkgooai.core.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(csrf -> csrf.disable())
            .authorizeExchange(exchanges -> exchanges
                // OAuth2 
                .pathMatchers(
                    "/api/oauth2/authorize",
                    "/api/oauth2/token",
                    "/api/oauth2/consent",
                    "/api/oauth2/jwks",
                    "/api/oauth2/.well-known/**"
                ).permitAll()
                .pathMatchers(
                    "/api/login",
                    "/api/logout"
                ).permitAll()
                // OAuth2 management
                .pathMatchers("/api/oauth2-admin/**").authenticated()
                // OAuth2 page
                .pathMatchers("/oauth2-page/**").permitAll()
                .anyExchange().authenticated()
            )
            .build();
    }
}
