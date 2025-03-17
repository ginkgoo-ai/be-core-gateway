package com.ginkgooai.core.gateway.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ginkgooai.core.gateway.security.GuestCodeGrantRequest;
import com.ginkgooai.core.gateway.security.GuestCodeTokenResponseClient;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GuestCodeAuthenticationFilter extends OncePerRequestFilter {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final GuestCodeTokenResponseClient tokenResponseClient;
    private final String clientRegistrationId;
    private final String redirectUri;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public GuestCodeAuthenticationFilter(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService,
            GuestCodeTokenResponseClient tokenResponseClient,
            String clientRegistrationId,
            String redirectUri) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientService = authorizedClientService;
        this.tokenResponseClient = tokenResponseClient;
        this.clientRegistrationId = clientRegistrationId;
        this.redirectUri = redirectUri;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                   FilterChain filterChain) throws ServletException, IOException {
        
        String guestCode = request.getParameter("guest_code");
        String resourceId = request.getParameter("resource_id");
        
        if (guestCode != null && resourceId != null && request.getRequestURI().contains("/oauth2/guest")) {
            try {
                // Get the client registration
                ClientRegistration clientRegistration = 
                        clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
                
                if (clientRegistration == null) {
                    throw new IllegalArgumentException(
                            "Client registration not found with ID: " + clientRegistrationId);
                }
                
                // Create OAuth2 token request
                GuestCodeGrantRequest grantRequest = new GuestCodeGrantRequest(
                        clientRegistration, guestCode, resourceId);
                
                // Exchange the guest code for an access token
                OAuth2AccessTokenResponse tokenResponse = tokenResponseClient.getTokenResponse(grantRequest);
                
                if (tokenResponse != null) {
                    // Create user principal from token response
                    Map<String, Object> userAttributes = extractUserAttributes(tokenResponse);
                    String principalName = (String) userAttributes.getOrDefault("guest_email", "guest-user");
                    
                    OAuth2User oauth2User = new DefaultOAuth2User(
                            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")), 
                            userAttributes, 
                            "sub");
                    
                    // Create authentication token
                    OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(
                            oauth2User, 
                            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")), 
                            clientRegistrationId);
                    
                    // Set authentication details
                    authenticationToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request));
                    
                    // Set authentication in the security context
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    
                    // Create an authorized client
                    OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                            clientRegistration,
                            principalName,
                            tokenResponse.getAccessToken(),
                            tokenResponse.getRefreshToken()
                    );
                    
                    // Store the authorized client
                    authorizedClientService.saveAuthorizedClient(
                            authorizedClient, authenticationToken);
                    
                    // Redirect to the target resource
                    response.sendRedirect(redirectUri + "/shortlist/" + resourceId);
                    return;
                }
            } catch (Exception e) {
                logger.error("Error processing guest code authentication", e);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid guest code: " + e.getMessage());
                return;
            }
        }
        
        filterChain.doFilter(request, response);
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
                        decodedPayload, new TypeReference<Map<String, Object>>() {});
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
