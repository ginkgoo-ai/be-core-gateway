package com.ginkgooai.core.gateway.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ginkgooai.core.gateway.security.ShareCodeGrantRequest;
import com.ginkgooai.core.gateway.security.ShareCodeTokenResponseClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ShareCodeAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final ShareCodeTokenResponseClient tokenResponseClient;
    private final String clientRegistrationId;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ShareCodeAuthenticationFilter(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService,
            ShareCodeTokenResponseClient tokenResponseClient,
            String clientRegistrationId,
            String defaultRedirectUri) {
        super(new AntPathRequestMatcher("/api/oauth2/share"));
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientService = authorizedClientService;
        this.tokenResponseClient = tokenResponseClient;
        this.clientRegistrationId = clientRegistrationId;

        setAuthenticationSuccessHandler((request, response, authentication) -> {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("status", "success");
            responseBody.put("authenticated", true);

            if (authentication.getPrincipal() instanceof OAuth2User) {
                OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
                responseBody.put("user", oauth2User.getAttributes());
            }

            objectMapper.writeValue(response.getWriter(), responseBody);
        });
        
        setAuthenticationFailureHandler((request, response, exception) -> {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                "Invalid share code: " + exception.getMessage());
        });
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        String shareCode = request.getParameter("share_code");

        if (shareCode == null) {
            throw new AuthenticationServiceException("share_code is required");
        }

        try {
            ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
            
            if (clientRegistration == null) {
                throw new AuthenticationServiceException(
                        "Client registration not found with ID: " + clientRegistrationId);
            }

            ShareCodeGrantRequest grantRequest = new ShareCodeGrantRequest(
                clientRegistration, shareCode);
            
            OAuth2AccessTokenResponse tokenResponse = tokenResponseClient.getTokenResponse(grantRequest);
            
            if (tokenResponse == null) {
                throw new AuthenticationServiceException("Failed to obtain access token");
            }

            Map<String, Object> userAttributes = extractUserAttributes(tokenResponse);
            OAuth2User oauth2User = new DefaultOAuth2User(
                Collections.emptyList(),
                userAttributes,
                    "sub");
            
            OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(
                    oauth2User,
                Collections.emptyList(), 
                    clientRegistrationId);
            
            OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                    clientRegistration,
                "ginkgoo-web-client",
                    tokenResponse.getAccessToken(),
                    tokenResponse.getRefreshToken()
            );
            
            authorizedClientService.saveAuthorizedClient(authorizedClient, authenticationToken);

            // Create a new security context and store it in the session
            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(authenticationToken);
            SecurityContextHolder.setContext(securityContext);

            // Store in session
            new HttpSessionSecurityContextRepository().saveContext(securityContext, request, response);
            
            return authenticationToken;
        } catch (Exception e) {
            throw new AuthenticationServiceException(e.getMessage(), e);
        }
    }

    private Map<String, Object> extractUserAttributes(OAuth2AccessTokenResponse tokenResponse) {
        Map<String, Object> attributes = new HashMap<>();

        // Try to extract claims from the access token (if it's a JWT)
        try {
            String accessToken = tokenResponse.getAccessToken().getTokenValue();
            String[] parts = accessToken.split("\\.");
            if (parts.length == 3) {  // It's a JWT
                String payload = parts[1];
                String decodedPayload = new String(Base64.getUrlDecoder().decode(payload));
                Map<String, Object> claims = objectMapper.readValue(
                        decodedPayload, new TypeReference<>() {
                        });
                attributes.putAll(claims);
            }
        } catch (Exception e) {
            logger.warn("Failed to parse access token as JWT", e);
        }

        // Extract claims from additional parameters
        tokenResponse.getAdditionalParameters().forEach((key, value) -> {
            if (key.equals("id_token")) {
                // Parse ID token and extract claims
                try {
                    String idToken = (String) value;
                    String[] parts = idToken.split("\\.");
                    if (parts.length == 3) {  // It's a JWT
                        String payload = parts[1];
                        String decodedPayload = new String(Base64.getUrlDecoder().decode(payload));
                        Map<String, Object> claims = objectMapper.readValue(
                                decodedPayload, new TypeReference<Map<String, Object>>() {});
                        attributes.putAll(claims);
                    }
                } catch (Exception e) {
                    logger.warn("Failed to parse ID token", e);
                }
            } else {
                attributes.put(key, value);
            }
        });

        // Ensure we have a subject
        if (!attributes.containsKey("sub") && attributes.containsKey("guest_email")) {
            attributes.put("sub", attributes.get("guest_email"));
        } else if (!attributes.containsKey("sub")) {
            attributes.put("sub", "guest-user");
        }

        return attributes;
    }
}