package com.ginkgooai.core.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ginkgooai.core.gateway.client.identity.UserClient;
import com.ginkgooai.core.gateway.client.identity.dto.UserInfo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class TokenEnabledCheckFilter extends OncePerRequestFilter {

	private final ObjectMapper objectMapper;

	private final UserClient userClient;

	private final SecurityContextRepository securityContextRepository;

	public TokenEnabledCheckFilter(UserClient userClient) {
		this.objectMapper = new ObjectMapper();
		this.userClient = userClient;
		this.securityContextRepository = new HttpSessionSecurityContextRepository();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (shouldSkip(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof OAuth2AuthenticationToken oauth2Authentication) {
			OAuth2User oauth2User = oauth2Authentication.getPrincipal();
			String userId = oauth2User.getName();

			boolean tokenEnabled = checkTokenEnabled((OAuth2AuthenticationToken) authentication);

			if (!tokenEnabled) {
				log.debug("User {} is disabled in token", userId);
				try {
					UserInfo userInfo = userClient.getUserById(userId).getBody();
					if (userInfo != null && userInfo.isEnabled()) {
						log.debug("User {} is enabled in db, updating token", userId);
						updateSecurityContextAndPersist(request, response, oauth2Authentication, userInfo);
						filterChain.doFilter(request, response);
						return;
					}
				}
				catch (Exception e) {
					logger.warn("Error while checking user status", e);
				}

				handleAccessDenied(request, response);
				return;
			}
		}

		filterChain.doFilter(request, response);
	}

	private boolean shouldSkip(HttpServletRequest request) {
		String path = request.getRequestURI();
		return path.startsWith("/authorized") || path.startsWith("/login") || path.startsWith("/api/workspace")
				|| path.startsWith("/api/identity/") || path.startsWith("/api/storage/v1/files")
				|| path.endsWith("/stream"); // Skip token check for SSE stream endpoints
	}

	private boolean checkTokenEnabled(OAuth2AuthenticationToken oauthToken) {
		OAuth2User oauth2User = oauthToken.getPrincipal();

		Object enabledAttr = oauth2User.getAttributes().get("enabled");
		return enabledAttr == null || !(enabledAttr instanceof Boolean) || (Boolean) enabledAttr;
	}

	private void updateSecurityContextAndPersist(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthenticationToken authentication, UserInfo userInfo) {
		Map<String, Object> attributes = new HashMap<>(authentication.getPrincipal().getAttributes());
		attributes.put("enabled", userInfo.isEnabled());

		OAuth2User updatedUser = new DefaultOAuth2User(authentication.getPrincipal().getAuthorities(), attributes,
				"sub");

		OAuth2AuthenticationToken updatedAuth = new OAuth2AuthenticationToken(updatedUser,
				authentication.getAuthorities(), authentication.getAuthorizedClientRegistrationId());

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(updatedAuth);

		SecurityContextHolder.setContext(securityContext);

		securityContextRepository.saveContext(securityContext, request, response);
	}

	private void handleAccessDenied(HttpServletRequest request, HttpServletResponse response) throws IOException {
		ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN,
				"User account is disabled");
		problemDetail.setTitle("Access Denied");
		problemDetail.setType(URI.create("/errors/account_not_activated"));
		problemDetail.setInstance(URI.create(request.getRequestURI()));

		response.setStatus(HttpStatus.FORBIDDEN.value());
		response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);

		objectMapper.writeValue(response.getOutputStream(), problemDetail);
	}
}
