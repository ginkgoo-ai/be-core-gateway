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
package com.ginkgooai.core.gateway.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

/**
 * @author Joe Grandja
 * @since 1.4
 */
@Slf4j
@Controller
public class DefaultController {

	@Value("${app.base-uri}")
	private String appBaseUri;
	
	@Value("${app.dev-uris}")
	private String appDevUrls;

	@GetMapping("/login")
	public String login(@RequestParam(name = "redirect_uri", required = false) String redirectUri,
						HttpServletRequest request) {
		HttpSession session = request.getSession();
		if (redirectUri != null && isValidRedirectUri(redirectUri)) {
			session.setAttribute("redirectUri", redirectUri);
		} else {
			session.setAttribute("redirectUri", appBaseUri);
		}
		log.debug("login with redirectUri:{}", redirectUri);
		return "redirect:/oauth2/authorization/ginkgoo-bff-client";
	}

	@GetMapping("/")
	public String root() {
		return "redirect:" + this.appBaseUri;
	}

	@GetMapping("/authorized")
	public String authorized(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		String redirectUri = appBaseUri;

		if (session != null) {
			redirectUri = (String) session.getAttribute("redirectUri");
			session.removeAttribute("redirectUri"); 
		}

		if (!isValidRedirectUri(redirectUri)) {
			log.debug("Invalid redirect URI:{}, using default:{} ", redirectUri, appBaseUri);
			redirectUri = appBaseUri;
		}

		return "redirect:" + redirectUri;
	}

	private boolean isValidRedirectUri(String redirectUri) {
		if (redirectUri == null) {
			return false;
		}
		try {
			URI uri = new URI(redirectUri);
			if (!uri.getScheme().equals("http") && !uri.getScheme().equals("https")) {
				return false;
			}

			// Get authority (host:port) from redirect URI
			String authority = uri.getAuthority();

			// Check against base URI
			URI baseUri = new URI(appBaseUri);
			if (authority.equals(baseUri.getAuthority())) {
				return true;
			}

			// Check against dev URLs if not empty
			if (appDevUrls != null && !appDevUrls.trim().isEmpty()) {
				return Arrays.stream(appDevUrls.split(","))
						.map(String::trim)
						.filter(url -> !url.isEmpty())
						.anyMatch(url -> {
							try {
								URI devUri = new URI(url);
								return authority.equals(devUri.getAuthority());
							} catch (URISyntaxException e) {
								return false;
							}
						});
			}

			return false;

		} catch (URISyntaxException e) {
			return false;
		}
	}


}
