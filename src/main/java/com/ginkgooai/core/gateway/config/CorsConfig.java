/*
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ginkgooai.core.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.util.ObjectUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Joe Grandja
 * @since 1.4
 */
@Configuration(proxyBeanMethods = false)
@Slf4j
public class CorsConfig {

	@Value("${app.base-uri}")
	private String appBaseUri;
	
	@Value("${app.dev-uris}")
	private String appDevUrls;

	@Value("${core-identity-uri}")
	private String identityUri;

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();

		List<String> origins = new ArrayList<>();
		origins.add("null");
		origins.add(appBaseUri);
		origins.add(identityUri);
		if (!ObjectUtils.isEmpty(appDevUrls)) {
			origins.addAll(
					Arrays.stream(appDevUrls.split(","))
							.map(String::trim)
							.filter(url -> !url.isEmpty())
							.toList()
			);
		}
		log.debug("Allowed origins: {}", origins);
		config.setAllowedOrigins(origins);
		
		config.addAllowedHeader("*");
		config.addAllowedHeader(HttpHeaders.CONTENT_TYPE);
		config.setAllowedMethods(Arrays.asList("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS","PATCH"));
		config.setAllowCredentials(true);
		config.setMaxAge(3600L);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		return source;
	}

}
