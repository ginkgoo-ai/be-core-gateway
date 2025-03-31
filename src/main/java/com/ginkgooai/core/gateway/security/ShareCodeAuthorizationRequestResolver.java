package com.ginkgooai.core.gateway.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class ShareCodeAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final RequestMatcher shareCodeRequestMatcher;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;
    private final String clientRegistrationId;

    public ShareCodeAuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository,
            String baseUri,
            String clientRegistrationId) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.shareCodeRequestMatcher = new AntPathRequestMatcher(baseUri + "/**");
        this.clientRegistrationId = clientRegistrationId;
        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository, baseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        if (this.shareCodeRequestMatcher.matches(request)) {
            String shareCode = request.getParameter("share_code");
            String resourceId = request.getParameter("resource_id");

            if (StringUtils.hasText(shareCode) && StringUtils.hasText(resourceId)) {
                return customAuthorizationRequest(request, shareCode, resourceId);
            }
        }
        
        // Fall back to default resolver for standard OAuth2 flows
        return this.defaultResolver.resolve(request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        if (this.shareCodeRequestMatcher.matches(request)) {
            String shareCode = request.getParameter("share_code");
            String resourceId = request.getParameter("resource_id");

            if (StringUtils.hasText(shareCode) && StringUtils.hasText(resourceId)) {
                return customAuthorizationRequest(request, shareCode, resourceId);
            }
        }
        
        // Fall back to default resolver for standard OAuth2 flows
        return this.defaultResolver.resolve(request, clientRegistrationId);
    }

    private OAuth2AuthorizationRequest customAuthorizationRequest(
        HttpServletRequest request, String shareCode, String resourceId) {
        
        ClientRegistration clientRegistration = 
                this.clientRegistrationRepository.findByRegistrationId(this.clientRegistrationId);
        
        if (clientRegistration == null) {
            throw new IllegalArgumentException(
                    "Client registration not found with ID: " + this.clientRegistrationId);
        }
        
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("share_code", shareCode);
        additionalParameters.put("resource_id", resourceId);
        
        // Build a custom authorization request for guest code flow
        OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest.authorizationCode()
                .clientId(clientRegistration.getClientId())
                .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
                .redirectUri(clientRegistration.getRedirectUri())
                .scopes(clientRegistration.getScopes())
                .state(request.getParameter("state"))
                .additionalParameters(additionalParameters);
        
        return builder.build();
    }
}
