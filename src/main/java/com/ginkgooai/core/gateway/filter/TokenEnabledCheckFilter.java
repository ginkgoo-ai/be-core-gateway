package com.ginkgooai.core.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;

public class TokenEnabledCheckFilter extends OncePerRequestFilter {

	private final ObjectMapper objectMapper;

	private final boolean needActiveAccount;

	public TokenEnabledCheckFilter(boolean needActiveAccount) {
		this.needActiveAccount = needActiveAccount;
		this.objectMapper = new ObjectMapper();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (shouldSkip(request) || !needActiveAccount) {
			filterChain.doFilter(request, response);
			return;
		}

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication instanceof OAuth2AuthenticationToken) {
			OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
			OAuth2User oauth2User = oauthToken.getPrincipal();

			Object enabledAttr = oauth2User.getAttributes().get("enabled");
			boolean isEnabled = enabledAttr == null || !(enabledAttr instanceof Boolean) || (Boolean) enabledAttr;

			if (!isEnabled) {
				handleAccessDenied(request, response);
				return;
			}
		}

		filterChain.doFilter(request, response);
	}

	private boolean shouldSkip(HttpServletRequest request) {
		String path = request.getRequestURI();
		return path.startsWith("/authorized") || path.startsWith("/login") || path.startsWith("/api/workspace")
				|| path.startsWith("/api/identity/");
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
