package com.ginkgooai.core.gateway.security;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URLEncoder;
import java.util.*;
import java.util.stream.Collectors;

/**
 * A client that exchanges a guest code for an access token.
 */
public class GuestCodeTokenResponseClient implements OAuth2AccessTokenResponseClient<GuestCodeGrantRequest> {
    private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";
    
    private final RestOperations restOperations;

    public GuestCodeTokenResponseClient() {
        this.restOperations = new RestTemplate();
    }

    public GuestCodeTokenResponseClient(RestOperations restOperations) {
        this.restOperations = restOperations;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(GuestCodeGrantRequest guestCodeGrantRequest) {
        ClientRegistration clientRegistration = guestCodeGrantRequest.getClientRegistration();
        
        // Prepare the request headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(clientRegistration.getClientId(), URLEncoder.encode(clientRegistration.getClientSecret()));
        
        // Prepare the request parameters
        MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
        formParameters.add(OAuth2ParameterNames.GRANT_TYPE, 
                guestCodeGrantRequest.getGrantType().getValue());
        formParameters.add("guest_code", guestCodeGrantRequest.getGuestCode());
//        formParameters.add("resource_id", guestCodeGrantRequest.getResourceId());
        
        // Add any additional parameters
        guestCodeGrantRequest.getAdditionalParameters().forEach((key, value) -> {
            formParameters.add(key, value.toString());
        });
        
        // Create the request entity
        URI uri = URI.create(clientRegistration.getProviderDetails().getTokenUri());
        RequestEntity<MultiValueMap<String, String>> request = 
                new RequestEntity<>(formParameters, headers, HttpMethod.POST, uri);
        
        ResponseEntity<Map<String, Object>> response;
        try {
            // Send the request
            response = this.restOperations.exchange(
                    request,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            );
        } catch (RestClientException ex) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: " 
                            + ex.getMessage(), null);
            throw new OAuth2AuthorizationException(oauth2Error, ex);
        }
        
        Map<String, Object> body = response.getBody();
        if (body == null) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
                    "Empty OAuth 2.0 Access Token Response", null);
            throw new OAuth2AuthorizationException(oauth2Error);
        }
        
        // Convert the response to OAuth2AccessTokenResponse
        return this.convertResponse(body);
    }

    private OAuth2AccessTokenResponse convertResponse(Map<String, Object> body) {
        String accessToken = (String) body.get(OAuth2ParameterNames.ACCESS_TOKEN);
        String tokenType = (String) body.get(OAuth2ParameterNames.TOKEN_TYPE);
        
        if (accessToken == null || tokenType == null) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
                    "Missing required fields in OAuth 2.0 Access Token Response", null);
            throw new OAuth2AuthorizationException(oauth2Error);
        }
        
        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse.withToken(accessToken)
                .tokenType(OAuth2AccessToken.TokenType.BEARER);
        
        if (body.containsKey(OAuth2ParameterNames.EXPIRES_IN)) {
            builder.expiresIn(((Number) body.get(OAuth2ParameterNames.EXPIRES_IN)).longValue());
        }
        
        if (body.containsKey(OAuth2ParameterNames.REFRESH_TOKEN)) {
            builder.refreshToken((String) body.get(OAuth2ParameterNames.REFRESH_TOKEN));
        }
        
        if (body.containsKey(OAuth2ParameterNames.SCOPE)) {
            String scope = (String) body.get(OAuth2ParameterNames.SCOPE);
            Set<String> scopes = scope != null ? 
                    Arrays.stream(scope.split(" ")).collect(Collectors.toSet()) : 
                    Collections.emptySet();
            builder.scopes(scopes);
        }
        
        // Add any additional parameters
        Map<String, Object> additionalParameters = new HashMap<>();
        body.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.ACCESS_TOKEN) && 
                !key.equals(OAuth2ParameterNames.TOKEN_TYPE) &&
                !key.equals(OAuth2ParameterNames.EXPIRES_IN) && 
                !key.equals(OAuth2ParameterNames.REFRESH_TOKEN) &&
                !key.equals(OAuth2ParameterNames.SCOPE)) {
                additionalParameters.put(key, value);
            }
        });
        
        return builder.additionalParameters(additionalParameters).build();
    }
}
