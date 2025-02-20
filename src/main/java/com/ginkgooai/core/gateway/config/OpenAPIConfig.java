package com.ginkgooai.core.gateway.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@OpenAPIDefinition
@Configuration
public class OpenAPIConfig {
    
    private static final String COOKIE_AUTH_NAME = "cookieAuth";

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI().info(new Info()
          .title("API Gateway Service")
          .description("API Gateway Service")
          .version("1.0.0"))
                .addSecurityItem(new SecurityRequirement().addList(COOKIE_AUTH_NAME))
                .components(new Components()
                        .addSecuritySchemes(COOKIE_AUTH_NAME, new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.COOKIE)
                                .name("SESSION")
                                .description("Session cookie for authentication")));
    }
}