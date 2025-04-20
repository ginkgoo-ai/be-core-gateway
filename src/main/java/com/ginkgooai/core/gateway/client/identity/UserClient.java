package com.ginkgooai.core.gateway.client.identity;

import com.ginkgooai.core.common.config.FeignConfig;
import com.ginkgooai.core.gateway.client.identity.dto.UserInfo;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "identity-service", url = "${core-identity-uri}", configuration = FeignConfig.class)
public interface UserClient {

	@GetMapping("/users/{id}")
	ResponseEntity<UserInfo> getUserById(@PathVariable String id);

}
