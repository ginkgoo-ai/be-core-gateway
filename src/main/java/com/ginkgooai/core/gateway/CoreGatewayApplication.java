package com.ginkgooai.core.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients
public class CoreGatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(CoreGatewayApplication.class, args);
    }
}