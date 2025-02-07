//package com.ginkgooai.core.gateway.config;
//
//import com.ginkgooai.core.gateway.util.IpUtils;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//@Slf4j
//public class GlobalRateLimitConfiguration {
//
//    private static final String ANONYMOUS_USER = "anonymous";
//
//    @Bean
//    public KeyResolver compositeKeyResolver() {
//        return exchange -> {
//            // Handle IP address
//            String ip = IpUtils.getClientIp(exchange.getRequest());
//
//            // Get principal name
//            return exchange.getPrincipal()
//                    .map(principal -> principal.getName())
//                    .defaultIfEmpty(ANONYMOUS_USER)
//                    .map(principalName -> String.format("rate_limit:%s:%s",
//                            ip, principalName));
//        };
//    }
//}