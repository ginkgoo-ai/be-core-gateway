package com.ginkgooai.core.gateway.client;

import com.ginkgooai.core.common.config.FeignConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "workspace-service", url="${core-workspace-uri}", configuration = FeignConfig.class)
public interface WorkspaceServiceClient {
    
    @GetMapping("/workspaces/members/{userId}/default")
    String getUserDefaultWorkspace(@PathVariable("userId") String userId);
    
}