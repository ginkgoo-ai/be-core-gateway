package com.ginkgooai.core.gateway.config;

import com.ginkgooai.core.common.utils.SecurityUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {
    
    @Bean
    public SecurityUtils securityUtils() {
        return new SecurityUtils();
    }
}
